package daemon

import "github.com/aau-network-security/haaukins-daemon/internal/database"

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
