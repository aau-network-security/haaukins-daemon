package daemon

import (
	"sync"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/agent"
	"github.com/aau-network-security/haaukins-daemon/internal/db"
)

type AdminClaims struct {
	Username     string `json:"username"`
	Email        string `json:"email"`
	Organization string `json:"organization"`
	Role         string `json:"role"`
	Jti          string `json:"jti"`
	Exp          int64  `json:"exp"`
}

type APIResponse struct {
	Status   string             `json:"status,omitempty"`
	Token    string             `json:"token,omitempty"`
	UserInfo *AdminUserReponse  `json:"userinfo,omitempty"`
	Users    []AdminUserReponse `json:"users,omitempty"`
	Orgs     []db.Organization  `json:"orgs,omitempty"`
	Agents   []AgentResponse    `json:"agents,omitempty"`
}

type EventPool struct {
	m      sync.RWMutex
	events map[string]Event
}

type Event struct {
	Config         EventConfig
	Teams          map[string]*Team
	Labs           map[string]*agent.Lab
	UnassignedLabs <-chan agent.Lab
}

type EventConfig struct {
	Type               int32     `json:"type"`
	Name               string    `json:"name" binding:"required"`
	Tag                string    `json:"tag" binding:"required"`
	TeamSize           int32     `json:"teamSize" binding:"required"`
	InitialLabs        int32     `json:"initialLabs,omitempty"`
	MaxLabs            int32     `json:"maxLabs" binding:"required"`
	VmName             string    `json:"vmName,omitempty"`
	ExerciseTags       []string  `json:"exerciseTags" binding:"required"`
	ExpectedFinishDate time.Time `json:"expectedFinishDate" binding:"required"`
	SecretKey          string    `json:"secretKey,omitempty"`
}

type Team struct {
	Tag      string
	Username string
	Email    string
	Lab      *agent.Lab
}
