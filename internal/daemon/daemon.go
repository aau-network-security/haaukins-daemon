package daemon

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/aau-network-security/haaukins-daemon/internal/database"
	eproto "github.com/aau-network-security/haaukins-daemon/internal/exercise/ex-proto"
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

type daemon struct {
	conf        *Config
	db          *database.Queries
	exClients   map[string]eproto.ExerciseStoreClient
	auditLogger *zerolog.Logger
	enforcer    *casbin.Enforcer
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
	{"g2", "exdbs::Admins", "objects::Admins"},
	{"g2", "registries::Admins", "objects::Admins"},
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
	db, gormDb, err := conf.Database.InitConn()
	if err != nil {
		log.Fatal().Err(err).Msg("[Haaukins-daemon] Failed to connect to database")
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

	// Getting exercise database connections stored in the database
	exersiceDatabases, err := db.GetExerciseDatabases(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("[Haaukins-daemon] Failed to get currently connected exercise databases")
		return nil, err
	}

	// Using a hashtable for exercise database connections
	// If the database name is not in the hashtable we know that the database is not connected
	log.Info().Msg("Connecting to currently stored exercise databases...")
	// TODO make a new exClient type which holds both the connection and the owner organization of each db
	// TODO And add a public boolean for exercise databases that are accessible by all.
	exClients := make(map[string]eproto.ExerciseStoreClient)
	for _, exDb := range exersiceDatabases {
		exDbConfig := ServiceConfig{
			Grpc:    exDb.Url,
			AuthKey: exDb.AuthKey,
			SignKey: exDb.SignKey,
			Enabled: exDb.Tls,
		}
		exClient, err := NewExerciseClientConn(exDbConfig)
		if err != nil {
			log.Warn().Err(err).Msgf("[exercise-service]: error on creating gRPC communication")

		} else {
			exClients[exDb.Name] = exClient
			log.Debug().Str("Url", exDbConfig.Grpc).Msg("Exercise service connected !")
		}
	}

	// Creating audit logger to log admin events seperately
	auditLogger := zerolog.New(newRollingFile(conf)).With().Logger()

	d := &daemon{
		conf:        conf,
		db:          db,
		exClients:   exClients,
		auditLogger: &auditLogger,
		enforcer:    enforcer,
	}
	return d, nil
}

func (d *daemon) Run() error {

	r := gin.Default()
	r.SetTrustedProxies([]string{"127.0.0.1"})
	d.setupRouters(r)
	return r.Run(":8080")
}

func (d *daemon) setupRouters(r *gin.Engine) {
	admin := r.Group("/api/v1/admin")
	event := r.Group("/api/v1/event")

	d.adminSubrouter(admin)
	d.eventSubrouter(event)
}

func exDbConnectRoutine() {

}
