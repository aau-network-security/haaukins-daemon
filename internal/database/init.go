package database

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type DbConfig struct {
	Host     string `yaml:"host"`
	Port     uint64 `yaml:"port"`
	DbName   string `yaml:"db_name"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func (conf *DbConfig) InitConn() (*Queries, error) {
	driver := "postgres"
	connectstring := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable", conf.Host, conf.Username, conf.Password, conf.DbName)
	// Setting up the database connection
	conn, err := sql.Open(driver, connectstring)
	if err != nil {
		return nil, err
	}
	// Pinging the connection to make sure that the db is alive
	if err := conn.Ping(); err != nil {
		return nil, err
	}
	db := New(conn)
	return db, nil
}
