package daemon

import (
	"strings"

	"github.com/gin-gonic/gin"
)

func unpackAdminClaims(c *gin.Context) AdminClaims {
	return AdminClaims{
		Username:     strings.ToLower((c.MustGet("sub").(string))),
		Email:        string(c.MustGet("email").(string)),
		Organization: string(c.MustGet("organization").(string)),
		Role:         string(c.MustGet("role").(string)),
		Jti:          string(c.MustGet("jti").(string)),
		Exp:          int64(c.MustGet("exp").(float64)),
	}
}
