package daemon

import (
	"errors"
	"io/ioutil"

	"github.com/aau-network-security/haaukins-daemon/internal/database"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v2"
)

type dbHandler struct {
	db *database.Queries
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

	// todo: replace all if statement with something better
	// change the way of handling configuration files

	if c.jwtSecret == "" {
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

func startAPI() {
	//log.Info("Starting API")
	r := gin.Default()
	// Setting up db connection
	db, err := database.InitConn()
	if err != nil {
		//log.Fatal("[NBI2] Failed to connect to database: ", err)
	}
	// Getting crmclient params

	dh := dbHandler{
		db: db,
	}

	dh.setupRouters(r)
	r.Run(":8080")
}

func (dh *dbHandler) setupRouters(r *gin.Engine) {
	admin := r.Group("/api/v1/admin")
	event := r.Group("/api/v1/event")

	dh.adminSubrouter(admin)
	dh.eventSubrouter(event)
}
