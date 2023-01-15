package daemon

import (
	"context"
	"sync"
	"time"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/aau-network-security/haaukins-daemon/internal/db"
	"github.com/aau-network-security/haaukins-exercises/proto"
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

type TeamClaims struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Jti      string `json:"jti"`
	Exp      int64  `json:"exp"`
	EventTag string `json:"eventTag"`
}

type APIResponse struct {
	Status         string                                  `json:"status,omitempty"`
	Token          string                                  `json:"token,omitempty"`
	UserInfo       *AdminUserReponse                       `json:"userinfo,omitempty"`
	Users          []AdminUserReponse                      `json:"users,omitempty"`
	Exercises      []*proto.Exercise                       `json:"exercises,omitempty"`
	Profiles       []ExerciseProfile                       `json:"profiles,omitempty"`
	EventExercises []EventExercise                         `json:"eventExercises,omitempty"`
	TeamLab        *AgentLab                               `json:"teamLab,omitempty"`
	Categories     []*proto.GetCategoriesResponse_Category `json:"categories,omitempty"`
	Orgs           []db.Organization                       `json:"orgs,omitempty"`
	Agents         []AgentResponse                         `json:"agents,omitempty"`
	Events         []db.Event                              `json:"events,omitempty"`
	TeamInfo       *TeamResponse                           `json:"teaminfo,omitempty"`
	EventInfo      *EventInfoResponse                      `json:"eventinfo,omitempty"`
}

type EventPool struct {
	M      sync.RWMutex
	Events map[string]*Event
}

type Event struct {
	M                          sync.RWMutex
	Config                     EventConfig
	Teams                      map[string]*Team
	Labs                       map[string]*AgentLab
	UnassignedBrowserLabs      chan *AgentLab
	UnassignedVpnLabs          chan *AgentLab
	TeamsWaitingForBrowserLabs chan *Team
	TeamsWaitingForVpnLabs     chan *Team
	EstimatedMemoryUsage       uint64
	EstimatedMemoryUsagePerLab uint64
}

type EventConfig struct {
	Type                  int32     `json:"type"`
	Name                  string    `json:"name" binding:"required"`
	Tag                   string    `json:"tag" binding:"required"`
	TeamSize              int32     `json:"teamSize" binding:"required"`
	InitialLabs           int32     `json:"initialLabs,omitempty"` // TODO Remove as this should no longre be used
	MaxLabs               int32     `json:"maxLabs" binding:"required"`
	VmName                string    `json:"vmName,omitempty"`
	ExerciseTags          []string  `json:"exerciseTags" binding:"required"`
	ExpectedFinishDate    time.Time `json:"expectedFinishDate" binding:"required"`
	SecretKey             string    `json:"secretKey,omitempty"`
	DynamicScoring        bool      `json:"dynamicScoring,omitempty"`
	DynamicMax            int32     `json:"dynamicMax,omitempty"`
	DynamicMin            int32     `json:"dynamicMin,omitempty"`
	DynamicSolveThreshold int32     `json:"dynamicSolveThreshold,omitempty"`
}

type Team struct {
	M                sync.RWMutex
	Username         string
	Email            string
	Status           TeamStatus
	Lab              *AgentLab
	RunningExercises map[string]struct{}
}

type ExerciseProfile struct {
	Id           int32                         `json:"id"`
	Name         string                        `json:"name"`
	Secret       bool                          `json:"secret"`
	Organization string                        `json:"organization"`
	Exercises    []db.GetExercisesInProfileRow `json:"exercises,omitempty"`
}

// Agent related types

type AgentPool struct {
	M                 sync.RWMutex
	Agents            map[string]*Agent
	AgentWeights      map[string]float64
	TotalMemInstalled uint64
}

type ResourceEstimates struct {
	EstimatedMemUsage       uint64
	EstimatedMemUsagePerLab uint64
	EstimatedMemorySpent    uint64
}

type Agent struct {
	Name         string
	Url          string
	Tls          bool
	Conn         *grpc.ClientConn   `json:"-"`
	Close        context.CancelFunc `json:"-"`
	Resources    AgentResources
	Weight       int32
	RequestsLeft int32 // Used for round robin algorithm
	QueuedTasks  uint32
	Heartbeat    string
	StateLock    bool
	Errors       []error
}

type AgentResources struct {
	Cpu                      float64
	Memory                   float64
	MemoryAvailable          uint64
	MemoryInstalled          uint64
	EstimatedMemoryAvailable uint64
	LabCount                 uint32
	VmCount                  uint32
	ContainerCount           uint32
}

type ParentAgent struct {
	Name string `json:"name"`
	Url  string `json:"url"`
	Tls  bool   `json:"tls"`
}
type AgentLab struct {
	ParentAgent          ParentAgent `json:"parentAgent"`
	EstimatedMemoryUsage uint64      `json:"-"`
	LabInfo              *aproto.Lab `json:"labInfo"`
}

type ExerciseStatus struct {
	Tag             string
	ContainerStatus map[string]uint
}
