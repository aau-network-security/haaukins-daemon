package daemon

import (
	"github.com/aau-network-security/haaukins-daemon/internal/database"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func verifyPassword(hash, password string) bool {
	byteHash := []byte(hash)
	bytePassword := []byte(password)

	if err := bcrypt.CompareHashAndPassword(byteHash, bytePassword); err != nil {
		return false
	}
	return true
}

func unpackAdminClaims(c *gin.Context) database.AdminUser {
	return database.AdminUser{
		Username:       string(c.MustGet("username").(string)),
		Email:          string(c.MustGet("email").(string)),
		OrganizationID: int32(c.MustGet("organization").(float64)),
		RoleID:         int32(c.MustGet("role").(float64)),
	}
}
