package daemon

import (
	"github.com/aau-network-security/haaukins-daemon/internal/database"
	"golang.org/x/crypto/bcrypt"
)

func authOrganizationAccess(admin AdminClaims, orgToAccess int32) bool {
	if admin.OrganizationID != orgToAccess {
		return false
	} else {
		return true
	}
}

func authRoleAccess(admin AdminClaims, role database.Role) bool {
	if role.WriteAll && !admin.WriteAll {
		return false
	}

	if role.ReadAll && !admin.ReadAll {
		return false
	}

	return true
}

func verifyPassword(hash, password string) bool {
	byteHash := []byte(hash)
	bytePassword := []byte(password)

	if err := bcrypt.CompareHashAndPassword(byteHash, bytePassword); err != nil {
		return false
	}
	return true
}
