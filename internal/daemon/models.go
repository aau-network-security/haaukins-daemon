package daemon

import (
	"container/list"
	"context"
	"sync"
	"time"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/aau-network-security/haaukins-daemon/internal/db"
	"github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/gorilla/websocket"
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
	Message        string                                  `json:"message,omitempty"`
	Token          string                                  `json:"token,omitempty"`
	UserInfo       *AdminUserReponse                       `json:"userinfo,omitempty"`
	Users          []AdminUserReponse                      `json:"users,omitempty"`
	Exercises      []*proto.Exercise                       `json:"exercises,omitempty"`
	Profiles       []ExerciseProfile                       `json:"profiles,omitempty"`
	EventExercises *EventExercisesResponse                 `json:"eventExercises,omitempty"`
	TeamLab        *LabResponse                            `json:"teamLab,omitempty"`
	Categories     []*proto.GetCategoriesResponse_Category `json:"categories,omitempty"`
	Orgs           []db.Organization                       `json:"orgs,omitempty"`
	Agents         []AgentResponse                         `json:"agents,omitempty"`
	Events         []EventResponse                         `json:"events,omitempty"`
	TeamInfo       *TeamResponse                           `json:"teaminfo,omitempty"`
	EventInfo      *EventInfoResponse                      `json:"eventinfo,omitempty"`
	LabHosts       []string                                `json:"labHosts,omitempty"`
}

type EventPool struct {
	M      sync.RWMutex      `json:"-"`
	Events map[string]*Event `json:"events,omitempty"`
}

type Event struct {
	M                          sync.RWMutex         `json:"-"`
	DbId                       int32                `json:"dbId"`
	StartedAt                  time.Time            `json:"startedAt"`
	Config                     EventConfig          `json:"config,omitempty"`
	Teams                      map[string]*Team     `json:"teams,omitempty"`
	Labs                       map[string]*AgentLab `json:"labs,omitempty"`
	UnassignedBrowserLabs      chan *AgentLab       `json:"-"`
	UnassignedVpnLabs          chan *AgentLab       `json:"-"`
	TeamsWaitingForBrowserLabs *list.List           `json:"-"` // Using linked list in order to remove teams from the queue again
	TeamsWaitingForVpnLabs     *list.List           `json:"-"`
	EstimatedMemoryUsage       uint64               `json:"estimatedMemoryUsage,omitempty"`
	EstimatedMemoryUsagePerLab uint64               `json:"estimatedMemoryUsagePerLab,omitempty"`
}

// TeamsWaitingForBrowserLabs chan *Team           `json:"-"`
// TeamsWaitingForVpnLabs     chan *Team           `json:"-"`

type EventConfig struct {
	Type                  int32     `json:"type"`
	Name                  string    `json:"name" binding:"required"`
	Tag                   string    `json:"tag" binding:"required"`
	TeamSize              int32     `json:"teamSize" binding:"required"`
	MaxLabs               int32     `json:"maxLabs" binding:"required"`
	VmName                string    `json:"vmName,omitempty"`
	ExerciseTags          []string  `json:"exerciseTags" binding:"required"`
	ExpectedFinishDate    time.Time `json:"expectedFinishDate" binding:"required"`
	PublicScoreBoard      bool      `json:"publicScoreBoard,omitempty"`
	SecretKey             string    `json:"secretKey,omitempty"`
	DynamicScoring        bool      `json:"dynamicScoring,omitempty"`
	DynamicMax            int32     `json:"dynamicMax,omitempty"`
	DynamicMin            int32     `json:"dynamicMin,omitempty"`
	DynamicSolveThreshold int32     `json:"dynamicSolveThreshold,omitempty"`
	ExerciseConfigs       []*aproto.ExerciseConfig
}

type Team struct {
	M                          sync.RWMutex               `json:"-"`
	Username                   string                     `json:"username,omitempty"`
	Email                      string                     `json:"email,omitempty"`
	Status                     TeamStatus                 `json:"status"`
	Lab                        *AgentLab                  `json:"lab,omitempty"`
	QueueElement               *list.Element              `json:"-"`
	ActiveWebsocketConnections map[string]*websocket.Conn `json:"-"`
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
	TotalMemInstalled uint64
}

type ResourceEstimates struct {
	EstimatedMemUsage       uint64
	EstimatedMemUsagePerLab uint64
	EstimatedMemorySpent    uint64
}

type Agent struct {
	M            sync.RWMutex `json:"-"`
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
	ParentAgent          ParentAgent      `json:"parentAgent,omitempty"`
	EstimatedMemoryUsage uint64           `json:"estimatedMemoryUsage,omitempty"`
	Conn                 *grpc.ClientConn `json:"-"`
	LabInfo              *aproto.Lab      `json:"labInfo,omitempty"`
	IsAssigned           bool             `json:"isAssigned,omitempty"`
	ExpiresAtTime        time.Time        `json:"expiresAtTime,omitempty"`
}

type Category struct {
	Name      string     `json:"name"`
	Exercises []Exercise `json:"exercises"`
}

type Exercise struct {
	ParentExerciseTag string  `json:"parentExerciseTag"`
	Static            bool    `json:"static"` // False if no docker containers for challenge
	Name              string  `json:"name"`
	Tag               string  `json:"tag"`
	Points            int     `json:"points"`
	Category          string  `json:"category"`
	Description       string  `json:"description"`
	Solved            bool    `json:"solved"`
	Solves            []Solve `json:"solves"`
}

type Solve struct {
	Date string `json:"date"`
	Team string `json:"team"`
}
