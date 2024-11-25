package daemon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/db"
	eproto "github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

type daemon struct {
	conf        *Config
	db          *db.Queries
	dbConn      *sql.DB
	exClient    eproto.ExerciseStoreClient
	agentPool   *AgentPool
	auditLogger *zerolog.Logger
	enforcer    *casbin.Enforcer
	cache       *redis.Client
	eventpool   *EventPool
	m           sync.RWMutex
}

const (
	orgExistsError                   = "organization already exists"
	userExistsError                  = "user already exists"
	passwordTooShortError            = "password must be at least 8 characters"
	incorrectUsernameOrPasswordError = "incorrect username or password"
)

var defaultPolicies = [][]string{
	{"role::superadmin", "Admins", "objects::Admins", "(read|write)"},
	{"role::superadmin", "Admins", "organizations", "(read|write)"},
}

var defaultObjectGroups = [][]string{
	{"g2", "events::Admins", "objects::Admins"},
	{"g2", "roles::Admins", "objects::Admins"},
	{"g2", "users::Admins", "objects::Admins"},
	{"g2", "exercises::Admins", "objects::Admins"},
	{"g2", "secretchals::Admins", "objects::Admins"},
	{"g2", "vms::Admins", "objects::Admins"},
	{"g2", "agents::Admins", "objects::Admins"},
	{"g2", "challengeProfiles::Admins", "objects::Admins"},
	{"g2", "settings::Admins", "objects::Admins"},
	{"g2", "role::superadmin", "roles::Admins"},
}

func NewConfigFromFile(path string) (*Config, error) {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var c Config
	err = yaml.Unmarshal(f, &c)
	if err != nil {
		return nil, err
	}

	if c.JwtSecret == "" {
		return nil, errors.New("missing signing key in configuration")
	}

	if c.AuditLog.Directory == "" {
		dir, _ := os.Getwd()
		c.AuditLog.Directory = filepath.Join(dir, "logs")
	}
	// In case paths has not been set, use working directory
	pwd, err := os.Getwd()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to get current working directory")
	}
	if c.StatePath == "" {
		c.StatePath = filepath.Join(pwd, "state")
	}

	if c.VmName == "" {
		c.VmName = "kali-v1-0-3"
	}

	if c.AuditLog.FileName == "" {
		c.AuditLog.FileName = "audit.log"
	}

	if c.AuditLog.MaxBackups == 0 {
		c.AuditLog.MaxBackups = 10
	}

	if c.AuditLog.MaxAge == 0 {
		c.AuditLog.MaxAge = 30
	}

	if c.AuditLog.MaxSize == 0 {
		c.AuditLog.MaxSize = 10
	}

	if c.Port == 0 {
		c.Port = 8080
	}

	if c.Database.Host == "" {
		c.Database.Host = "localhost"
	}

	if c.Database.DbName == "" {
		c.Database.DbName = "haaukins"
	}

	if c.Database.Username == "" {
		c.Database.Username = "haaukins"
	}

	if c.Database.Username == "" {
		c.Database.Password = "haaukins"
	}
	if c.EventRetention == 0 {
		c.EventRetention = 30 // Default to 30 days of retention
	}

	if c.LabExpiryDuration == 0 {
		c.LabExpiryDuration = 60 * 5 // Default 5 hour duration
	}

	return &c, nil
}

func New(conf *Config) (*daemon, error) {
	ctx := context.Background()
	log.Info().Msg("Creating daemon...")

	// Setting up the state path
	if _, err := os.Stat(conf.StatePath); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(conf.StatePath, os.ModePerm)
		if err != nil {
			log.Error().Err(err).Msg("Error creating dir")
		}
	}
	// TODO rewrte init function if filtered adapter is used
	//Setting up database connection
	queries, gormDb, dbConn, err := conf.Database.InitConn()
	if err != nil {
		log.Fatal().Err(err).Msg("[Haaukins-daemon] Failed to connect to database")
	}

	// Connecting to the exercise service
	log.Info().Msg("connecting to exercise service")
	exClient, err := NewExerciseClientConn(conf.ExerciseService)
	if err != nil {
		log.Fatal().Err(err).Msgf("[exercise-service]: error on creating gRPC communication")

	}

	eventPool, err := resumeState(conf.StatePath, conf.LabExpiryDuration)
	if err != nil {
		eventPool = &EventPool{
			M:      sync.RWMutex{},
			Events: make(map[string]*Event),
		}
	}
	if eventPool == nil {
		eventPool = &EventPool{
			M:      sync.RWMutex{},
			Events: make(map[string]*Event),
		}
	}

	// Connecting to all haaukins agents
	log.Info().Msg("Connecting to haaukins agents...")
	agentsInDb, err := queries.GetAgents(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("could not get haaukins agents from database")
	}
	agents := make(map[string]*Agent)
	agentPool := &AgentPool{
		M: sync.RWMutex{},
	}

	var wg sync.WaitGroup
	var m sync.Mutex
	for _, a := range agentsInDb {
		wg.Add(1)
		go func(agents map[string]*Agent, a db.Agent) {
			agentConfig := ServiceConfig{
				Grpc:       a.Url,
				AuthKey:    a.AuthKey,
				SignKey:    a.SignKey,
				TLSEnabled: a.Tls,
			}
			conn, memoryInstalled, err := NewAgentConnection(agentConfig)
			if err != nil {
				log.Warn().Err(err).Msg("error connecting to agent at url: " + agentConfig.Grpc)
				wg.Done()
			} else {
				streamCtx, cancel := context.WithCancel(context.Background())
				var agentToAdd = &Agent{
					M:            sync.RWMutex{},
					Name:         a.Name,
					Url:          a.Url,
					Tls:          a.Tls,
					Conn:         conn,
					Weight:       a.Weight,
					RequestsLeft: a.Weight,
					StateLock:    a.Statelock,
					Errors:       []error{},
					Close:        cancel,
					Resources: AgentResources{
						MemoryInstalled: memoryInstalled,
					},
				}
				if err := agentPool.connectToStreams(streamCtx, agentToAdd, eventPool, conf.StatePath); err != nil {
					log.Error().Err(err).Msg("error connecting to agent streams")
					wg.Done()
					return
				}
				m.Lock()
				agents[a.Name] = agentToAdd
				m.Unlock()
				wg.Done()
			}
		}(agents, a)
	}
	wg.Wait()
	agentPool.Agents = agents

	// Reassign labs to their agent since the connection is not stored in state
	for _, event := range eventPool.Events {
		for _, l := range event.Labs {
			for _, agent := range agentPool.Agents {
				if l.ParentAgent.Name == agent.Name {
					log.Debug().Msg("Found agent for lab")
					l.Conn = agent.Conn
				}
			}
		}
	}

	log.Debug().Msg("added agents to agent pool")
	// dataSource := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable", conf.Database.Host, conf.Database.Username, conf.Database.Password, conf.Database.DbName, conf.Database.Port)
	// adapter, err := gormadapter.NewFilteredAdapter("postgres", dataSource, true)
	// if err != nil {
	// 	log.Fatal().Err(err).Msg("Failed to create casbin adapter")
	// }

	adapter, err := gormadapter.NewAdapterByDB(gormDb)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create casbin adapter")
	}

	enforcer, err := casbin.NewEnforcer("config/rbac_model.conf", adapter, false)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create casbin enforcer")
	}

	// filter := gormadapter.Filter{
	// 	V1: []string{"Admins"},
	// 	V2: []string{"objects::Admins"},
	// }
	// if err := enforcer.LoadFilteredPolicy(filter); err != nil {
	// 	log.Fatal().Err(err).Msg("Error loading policies")
	// }

	// Inserting default casbin policies if they don't already exist
	for _, p := range defaultPolicies {
		if !enforcer.HasPolicy(p) {
			if _, err := enforcer.AddPolicy(p); err != nil {
				log.Fatal().Err(err).Msg("Error adding missing policy")
			}
		}
	}

	for _, g := range defaultObjectGroups {
		if !enforcer.HasNamedGroupingPolicy(g[0], g[1:]) {
			if _, err := enforcer.AddNamedGroupingPolicy(g[0], g[1:]); err != nil {
				log.Fatal().Err(err).Msg("Error adding missing policy")
			}
		}
	}
	// Adding initial admin account in admin org
	if !enforcer.HasGroupingPolicy("admin", "role::superadmin", "Admins") {
		if _, err := enforcer.AddGroupingPolicy("admin", "role::superadmin", "Admins"); err != nil {
			log.Fatal().Err(err).Msg("Error administrator")
		}
	}

	// Creating audit logger to log admin events seperately in a file
	auditLogger := zerolog.New(newRollingFile(conf)).With().Logger()

	d := &daemon{
		conf:        conf,
		db:          queries,
		dbConn:      dbConn,
		exClient:    exClient,
		agentPool:   agentPool,
		auditLogger: &auditLogger,
		enforcer:    enforcer,
		eventpool:   eventPool,
	}
	return d, nil
}

func (d *daemon) Run() error {

	r := gin.Default()
	r.SetTrustedProxies([]string{"127.0.0.1"})
	// Setting up CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"POST", "GET", "OPTIONS", "PUT", "DELETE", "PATCH"},
		AllowHeaders:     []string{"Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization", "Accept", "Origin", "Cache-Control", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	r.Use(gin.Recovery())

	if d.conf.TestDelay.Enabled {
		r.Use(d.delayMiddleware())
	}
	d.setupRouters(r)

	go d.labExpiryRoutine()

	eventRoutineTicker := time.NewTicker(10 * time.Second)
	go d.eventRetentionRoutine(eventRoutineTicker)

	agentSyncRoutineTicker := time.NewTicker(30 * time.Second)
	go d.agentSyncRoutine(agentSyncRoutineTicker)

	agentReconnectionTicker := time.NewTicker(10 * time.Second)
	go d.agentReconnectionRoutine(agentReconnectionTicker)

	listeningAddress := fmt.Sprintf("%s:%d", d.conf.ListeningIp, d.conf.Port)
	return r.Run(listeningAddress)
}

func (d *daemon) setupRouters(r *gin.Engine) {
	admin := r.Group("/v1/admin")
	event := r.Group("/v1/event")

	d.adminSubrouter(admin)
	d.eventSubrouter(event)
}

func (d *daemon) labExpiryRoutine() {
	log.Info().Msg("[lab-expiry-routine] starting routine")
	for {
		time.Sleep(1 * time.Second)
		events := d.eventpool.GetAllEvents()
		for _, event := range events {
			var wg sync.WaitGroup
			anyLabsClosed := false
			event.M.RLock()
			for _, team := range event.Teams {
				team.M.RLock()
				if team.Lab != nil {
					if time.Now().After(team.Lab.ExpiresAtTime) {
						if team.Lab.Conn != nil {
							anyLabsClosed = true
							wg.Add(1)
							go func(team *Team, event *Event) {
								defer wg.Done()
								defer func() {
									event.M.Lock()
									delete(event.Labs, team.Lab.LabInfo.Tag)
									event.M.Unlock()
									team.M.Lock()
									team.Lab = nil
									team.M.Unlock()
									saveState(d.eventpool, d.conf.StatePath)
									sendCommandToTeam(team, updateTeam)
								}()
								log.Info().Str("Team", team.Username).Msg("[lab-expiry-routine] closing lab due to expiry")
								if err := team.Lab.close(); err != nil {
									log.Error().Err(err).Msg("[lab-expiry-routine] error closing lab in ")
									return
								}

							}(team, event)
						} else {
							log.Warn().Msg("[lab-expiry-routine] lab had nil connection")
						}
					}
				}
				team.M.RUnlock()
			}
			event.M.RUnlock()
			wg.Wait()
			if anyLabsClosed {
				broadCastCommandToEventTeams(event, updateEventInfo)
			}
		}
	}
}

// This routine handles the deletion of events that has been closed for more than a set time
// Using database relations deleting just the event will trigger a cascade delete for all related data for that event
// It also closes running events if they have passed their expected finish time.
func (d *daemon) eventRetentionRoutine(ticker *time.Ticker) {
	log.Info().Msg("[event-retention-routine] starting routine")
	for {
		select {
		case <-ticker.C:
			ctx := context.Background()
			events, err := d.db.GetAllEvents(ctx)
			if err != nil {
				log.Warn().Err(err).Msg("[event-retention-routine] error getting events for")
				continue
			}
			for _, event := range events {
				if event.Status == StatusRunning {
					if time.Now().After(event.FinishExpected) {
						log.Debug().Str("eventTag", event.Tag).Msg("[event-retention-routine] Closing event")
						if err := d.agentPool.closeEnvironmentOnAllAgents(ctx, event.Tag); err != nil {
							log.Warn().Err(err).Msg("[event-retention-routine] error closing environments on agents")
							continue
						}

						newEventTag := event.Tag + "-" + strconv.Itoa(int(time.Now().Unix()))
						closeEventParams := db.CloseEventParams{
							Newtag: newEventTag,
							Oldtag: event.Tag,
							Finishedat: sql.NullTime{
								Time:  time.Now(),
								Valid: true,
							},
							Newstatus: StatusClosed,
						}

						if err := d.db.CloseEvent(ctx, closeEventParams); err != nil {
							log.Warn().Err(err).Msg("[event-retention-routine] error updating event db status to closed")
						}

						if err := d.eventpool.RemoveEvent(event.Tag); err != nil {
							log.Warn().Err(err).Msg("[event-retention-routine] event not found in event pool, something else has removed")
						}

						saveState(d.eventpool, d.conf.StatePath)
					}
				} else if event.Status == StatusClosed {
					if time.Now().After(event.FinishedAt.Time.AddDate(0, 0, int(d.conf.EventRetention))) {
						log.Debug().Str("eventTag", event.Tag).Msg("[event-retention-routine] deleting event and related data from db")
						if err := d.db.DeleteEventById(ctx, event.ID); err != nil {
							log.Warn().Str("eventTag", event.Tag).Err(err).Msg("[event-retention-routine] error deleting event from database")
							continue
						}
					}
				}
			}
		}
	}
}
