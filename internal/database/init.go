package database

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

func InitConn() (*Queries, error) {
	driver := "postgres"
	host := os.Getenv("DB_HOST")
	username := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	connectstring := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable", host, username, password, dbname)
	conn, err := sql.Open(driver, connectstring)
	if err != nil {
		return nil, err
	}
	db := New(conn)
	return db, nil
}
