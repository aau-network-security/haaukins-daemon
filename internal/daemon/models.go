package daemon

import (
	"sync"

	"github.com/aau-network-security/haaukins-daemon/internal/agent"
	"github.com/aau-network-security/haaukins-daemon/internal/database"
	"github.com/gin-gonic/gin"
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
	Status string                        `json:"status,omitempty"`
	Token  string                        `json:"token,omitempty"`
	User   *database.GetAdminUserNoPwRow `json:"user,omitempty"`
	Users  []database.GetAdminUsersRow   `json:"users,omitempty"`
	Orgs   []database.Organization       `json:"orgs,omitempty"`
}

type eventPool struct {
	m               sync.RWMutex
	host            string
	notFoundHandler gin.HandlerFunc
	events          map[string]event
}

type event struct {
	tag            string
	teams          map[string]team
	frontendPort   uint
	labs           map[string]agent.Lab
	exercises      []string
	unassignedLabs <-chan agent.Lab
}

type team struct {
}
