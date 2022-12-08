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
	Name       string
	Conn       *grpc.ClientConn   `json:"-"`
	Close      context.CancelFunc `json:"-"`
	Resources  Resources
	Heartbeat  string
	StateLock  bool
	ActiveLabs uint64
	Errors     []error
}

type Resources struct {
	Cpu            float64
	Memory         float64
	LabCount       uint32
	VmCount        uint32
	ContainerCount uint32
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
