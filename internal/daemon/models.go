package daemon

import (
	"context"
	"sync"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/db"
	"google.golang.org/grpc"
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
	M      sync.RWMutex
	Events map[string]*Event
}

type Event struct {
	Config              EventConfig
	Teams               map[string]*Team
	Labs                map[string]*AgentLab
	UnassignedLabs      chan AgentLab
	TeamsWaitingForLabs chan Team
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
	Lab      *AgentLab
}

// Agent related types

type AgentPool struct {
	M      sync.RWMutex
	Agents map[string]*Agent
}

type Agent struct {
	Name       string
	Conn       *grpc.ClientConn   `json:"-"`
	Close      context.CancelFunc `json:"-"`
	Resources  AgentResources
	Heartbeat  string
	StateLock  bool
	ActiveLabs uint64
	Errors     []error
}

type AgentResources struct {
	Cpu            float64
	Memory         float64
	LabCount       uint32
	VmCount        uint32
	ContainerCount uint32
}
type AgentLab struct {
	Tag         string
	ParentAgent string
	IsVPN       bool
	Exercises   map[string]ExerciseStatus
}

type ExerciseStatus struct {
	Tag             string
	ContainerStatus map[string]uint
}
