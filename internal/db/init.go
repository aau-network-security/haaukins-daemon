package db

import (
	"fmt"

	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DbConfig struct {
	Host           string `yaml:"host"`
	Port           uint64 `yaml:"port"`
	DbName         string `yaml:"dbName"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
}

func (conf *DbConfig) InitConn() (*Queries, *gorm.DB, error) {
	// driver := "postgres"
	connectstring := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable", conf.Host, conf.Username, conf.Password, conf.DbName, conf.Port)

	// Setting up casbin adapter
	gormDb, err := gorm.Open(postgres.Open(connectstring), &gorm.Config{})
	if err != nil {
		return nil, nil, err
	}

	// Setting up sqlc connection
	conn, err := gormDb.DB()
	if err != nil {
		return nil, nil, err
	}
	// Pinging the connection to make sure that the db is alive
	if err := conn.Ping(); err != nil {
		return nil, nil, err
	}

	db := New(conn)
	return db, gormDb, nil
}
