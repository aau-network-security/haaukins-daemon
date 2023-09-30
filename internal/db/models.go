// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.20.0

package db

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type AdminUser struct {
	ID           int32
	Sid          uuid.UUID
	Username     string
	Password     string
	FullName     string
	Email        string
	Role         string
	LabQuota     sql.NullInt32
	Organization string
}

type Agent struct {
	ID        int32
	Name      string
	Url       string
	Weight    int32
	SignKey   string
	AuthKey   string
	Tls       bool
	Statelock bool
}

type Event struct {
	ID                    int32
	Tag                   string
	Type                  int32
	Organization          string
	Name                  string
	MaxLabs               int32
	Status                int32
	Frontend              string
	Exercises             string
	PublicScoreboard      bool
	DynamicScoring        bool
	DynamicMax            int32
	DynamicMin            int32
	DynamicSolveThreshold int32
	StartedAt             time.Time
	FinishExpected        time.Time
	FinishedAt            sql.NullTime
	Createdby             string
	Secretkey             string
}

type Frontend struct {
	ID       int32
	Name     string
	Image    string
	Memorymb sql.NullInt32
}

type Organization struct {
	ID         int32
	Name       string
	OwnerUser  string
	OwnerEmail string
	LabQuota   sql.NullInt32
}

type Profile struct {
	ID           int32
	Name         string
	Secret       bool
	Description  string
	Public       bool
	Organization string
}

type ProfileChallenge struct {
	ID        int32
	Tag       string
	Name      string
	ProfileID int32
}

type Solf struct {
	ID       int32
	Tag      string
	EventID  int32
	TeamID   int32
	SolvedAt time.Time
}

type Team struct {
	ID         int32
	Tag        string
	EventID    int32
	Email      string
	Username   string
	Password   string
	CreatedAt  time.Time
	LastAccess sql.NullTime
}
