package agent

import (
	"context"
	"sync"

	"google.golang.org/grpc"
)

type AgentPool struct {
	M      sync.RWMutex
	Agents map[string]*Agent
}

type Agent struct {
	Name      string
	Conn      *grpc.ClientConn
	Close     context.CancelFunc
	Resources Resources
	Heartbeat string
	StateLock bool
	Errors    []error
}

type Resources struct {
	Memory string
	Cpu    string
}
type Lab struct {
	tag         string
	guacPort    uint
	parentAgent string
	isVPN       bool
	exercises   map[string]Exercise
}

type Exercise struct {
	tag             string
	containerStatus map[string]uint
}
