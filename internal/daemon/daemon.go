package daemon

import (
	"context"
	"errors"
	"io/ioutil"

	"github.com/aau-network-security/haaukins-daemon/internal/database"
	eproto "github.com/aau-network-security/haaukins-daemon/internal/exercise/ex-proto"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

type daemon struct {
	conf      *Config
	db        *database.Queries
	exClients map[string]eproto.ExerciseStoreClient
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
	db, err := conf.Database.InitConn()
	if err != nil {
		log.Fatal().Err(err).Msg("[Haaukins-daemon] Failed to connect to database")
		return nil, err
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
	exClients := make(map[string]eproto.ExerciseStoreClient)
	for _, exDb := range exersiceDatabases {
		exDbConfig := ServiceConfig{
			Grpc:    exDb.Url.String,
			AuthKey: exDb.AuthKey.String,
			SignKey: exDb.SignKey.String,
			Enabled: true,
		}
		exClient, err := NewExerciseClientConn(exDbConfig)
		if err != nil {
			log.Warn().Err(err).Msgf("[exercise-service]: error on creating gRPC communication")

		} else {
			exClients[exDb.Name.String] = exClient
			log.Debug().Str("Url", exDbConfig.Grpc).Msg("Exercise service connected !")
		}
	}

	d := &daemon{
		conf:      conf,
		db:        db,
		exClients: exClients,
	}
	return d, nil
}

func (d *daemon) Run() error {

	r := gin.Default()
	d.setupRouters(r)
	return r.Run(":8080")
}

func (d *daemon) setupRouters(r *gin.Engine) {
	admin := r.Group("/api/v1/admin")
	event := r.Group("/api/v1/event")

	d.adminSubrouter(admin)
	d.eventSubrouter(event)
}
