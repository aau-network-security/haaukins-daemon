package daemon

import (
	"github.com/gin-gonic/gin"
)

func unpackAdminClaims(c *gin.Context) AdminClaims {
	return AdminClaims{
		Username:       string(c.MustGet("sub").(string)),
		Email:          string(c.MustGet("email").(string)),
		OrganizationID: int32(c.MustGet("organization_id").(float64)),
		WriteAll:       bool(c.MustGet("write_all").(bool)),
		ReadAll:        bool(c.MustGet("read_all").(bool)),
		WriteLocal:     bool(c.MustGet("write_local").(bool)),
		ReadLocal:      bool(c.MustGet("read_local").(bool)),
		Jti:            string(c.MustGet("jti").(string)),
		Exp:            int64(c.MustGet("exp").(float64)),
	}
}
