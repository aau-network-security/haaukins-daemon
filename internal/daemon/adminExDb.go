package daemon

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (d *daemon) adminExDbSubrouter(r *gin.RouterGroup) {
	exDb := r.Group("/exdbs")
	exDb.Use(corsMiddleware())
	exDb.Use(d.adminAuthMiddleware())

	exDb.POST("", d.addExDb)
	exDb.GET("", d.listExDbs)
	exDb.PUT("", d.updateExDb)
	exDb.DELETE("", d.deleteExDb)
}

type adminExDbRequest struct {
	DbName       string `json:"db_name"`
	Organization string `json:"organization"`
	Url          string `json:"url"`
	SignKey      string `json:"signkey"`
	AuthKey      string `json:"authkey"`
}

func (d *daemon) addExDb(c *gin.Context) {
	ctx := context.Background()
	// Unpack user request into go struct
	var req adminExDbRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}

	// Unpack the jwt claims passed in the gin context to a struct
	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("NewExDb", req.DbName).
		Msg("Trying to add a new exDb")

}

func (d *daemon) listExDbs(c *gin.Context) {

}

func (d *daemon) updateExDb(c *gin.Context) {

}

func (d *daemon) deleteExDb(c *gin.Context) {

}

func (d *daemon) reconnect(c *gin.Context) {

}
