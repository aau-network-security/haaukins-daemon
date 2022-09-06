package agent

import (
	"sync"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
)

type AgentPool struct {
	M      sync.RWMutex
	Agents map[string]HaaukinsAgent
}

type HaaukinsAgent struct {
	Client    aproto.AgentClient
	Capacity  int32
	CapUsed   int32
	Heartbeat string
	Errors    []error
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
