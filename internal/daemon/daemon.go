package daemon

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/agent"
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
	exClient    eproto.ExerciseStoreClient
	agentPool   *agent.AgentPool
	auditLogger *zerolog.Logger
	enforcer    *casbin.Enforcer
	cache       *redis.Client
	eventpool   *eventPool
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

	return &c, nil
}

func New(conf *Config) (*daemon, error) {
	ctx := context.Background()
	log.Info().Msg("Creating daemon...")
	// TODO rewrte init function if filtered adapter is used
	//Setting up database connection
	db, gormDb, err := conf.Database.InitConn()
	if err != nil {
		log.Fatal().Err(err).Msg("[Haaukins-daemon] Failed to connect to database")
	}

	// Connecting to the exercise service
	log.Info().Msg("connecting to exercise service")
	exClient, err := NewExerciseClientConn(conf.ExerciseService)
	if err != nil {
		log.Fatal().Err(err).Msgf("[exercise-service]: error on creating gRPC communication")

	}

	// Connecting to all haaukins agents
	log.Info().Msg("Connecting to haaukins agents...")
	agentsInDb, err := db.GetHaaukinsAgents(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("could not get haaukins agents from database")
	}
	agents := make(map[string]agent.HaaukinsAgent)
	for _, a := range agentsInDb {
		agentConfig := ServiceConfig{
			Grpc:       a.Url,
			AuthKey:    a.AuthKey,
			SignKey:    a.SignKey,
			TLSEnabled: a.Tls,
		}
		client, err := NewAgentClientConnection(agentConfig)
		if err != nil {
			log.Warn().Err(err).Msg("error connecting to agent at url: " + agentConfig.Grpc)
		} else {
			var agentToAdd = agent.HaaukinsAgent{
				Client:   client,
				Capacity: a.Capacity,
				CapUsed:  0,
			}
			agents[a.Name] = agentToAdd
		}
	}
	agentPool := agent.AgentPool{
		Agents: agents,
	}
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
		db:          db,
		exClient:    exClient,
		agentPool:   &agentPool,
		auditLogger: &auditLogger,
		enforcer:    enforcer,
	}
	return d, nil
}

func (d *daemon) Run() error {

	r := gin.Default()
	r.SetTrustedProxies([]string{"127.0.0.1"})
	// Setting up CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"POST", "GET", "OPTIONS", "PUT", "DELETE"},
		AllowHeaders:     []string{"Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization", "Accept", "Origin", "Cache-Control", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	d.setupRouters(r)
	return r.Run(":8080")
}

func (d *daemon) setupRouters(r *gin.Engine) {
	admin := r.Group("/api/v1/admin")
	event := r.Group("/api/v1/event")

	d.adminSubrouter(admin)
	d.eventSubrouter(event)
}
