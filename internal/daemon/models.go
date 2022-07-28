package daemon

import "github.com/aau-network-security/haaukins-daemon/internal/database"

type AdminClaims struct {
	Username       string `json:"username"`
	Email          string `json:"email"`
	OrganizationID int32  `json:"organization_id"`
	RoleID         int32  `json:"role_id"`
	WriteAll       bool   `json:"write_all"`
	ReadAll        bool   `json:"read_all"`
	WriteLocal     bool   `json:"write_local"`
	ReadLocal      bool   `json:"read_local"`
	Jti            string `json:"jti"`
	Exp            int64  `json:"exp"`
}

type APIResponse struct {
	Status string                        `json:"status,omitempty"`
	Token  string                        `json:"token,omitempty"`
	User   *database.GetAdminUserNoPwRow `json:"user,omitempty"`
	Users  []database.GetAdminUsersRow   `json:"users,omitempty"`
}
