package daemon

import "github.com/aau-network-security/haaukins-daemon/internal/database"

func authOrganizationAccess(admin AdminClaims, orgToAccess int32) bool {
	if admin.OrganizationID != orgToAccess {
		return false
	} else {
		return true
	}
}

func authRoleAssignment(admin AdminClaims, role database.Role) bool {
	if role.WriteAll && !admin.WriteAll {
		return false
	}

	if role.ReadAll && !admin.ReadAll {
		return false
	}

	return true
}
