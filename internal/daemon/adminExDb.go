package daemon

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/database"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (d *daemon) adminExDbSubrouter(r *gin.RouterGroup) {
	exDb := r.Group("/exdbs")
	exDb.Use(d.adminAuthMiddleware())

	exDb.POST("", d.addExDb)
	exDb.GET("", d.listExDbs)
	exDb.PUT("", d.updateExDb)
	exDb.DELETE("", d.deleteExDb)
}

type adminExDbRequest struct {
	ExDbName string `json:"exdb_name"`
	Url      string `json:"url"`
	SignKey  string `json:"signkey"`
	AuthKey  string `json:"authkey"`
	TLS      bool   `json:"tls"`
}

// TODO Add a public parameter for shared databases like AAU's
// TODO Need to figure out a smart way to handle secret chals, as only the exDbs owner should have access to them.
// TODO Maybe add the organization owner to exdb map, then make use of casbin to check if user has access to secretchals::exdbOwnerDomain

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
		Str("NewExDb", req.ExDbName).
		Msg("Trying to add a new exDb")

	sub := admin.Username
	dom := admin.Organization
	obj := fmt.Sprintf("exdbs::%s", admin.Organization)
	act := "write"
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing user creation")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		exDbConfig := ServiceConfig{
			Grpc:    req.Url,
			AuthKey: req.AuthKey,
			SignKey: req.SignKey,
			Enabled: req.TLS,
		}
		// Check the connection status, return if connection times out or errors out
		exClient, err := NewExerciseClientConn(exDbConfig)
		if err != nil {
			log.Error().Err(err).Msgf("[exercise-service]: Error when connecting to new exercise service")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("Error connecting to specified exercise service: %s", err)})
			return
		}
		// Connected to exercise service adding to database
		exists, err := d.addExDbQuery(ctx, req, admin)
		if err != nil {
			log.Error().Err(err).Msgf("Error adding exercise to db or policy")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		if exists {
			c.JSON(http.StatusBadRequest, APIResponse{Status: "An exercise database with that name already exists"})
			return
		}
		// Adding to hashmap of connected exercise databases
		// TODO Consider adding a mutex lock here?
		d.exClients[req.ExDbName] = exClient
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) listExDbs(c *gin.Context) {

}

func (d *daemon) updateExDb(c *gin.Context) {

}

func (d *daemon) deleteExDb(c *gin.Context) {

}

func (d *daemon) reconnect(c *gin.Context) {

}

func (d *daemon) addExDbQuery(ctx context.Context, newExDb adminExDbRequest, admin AdminClaims) (bool, error) {
	// Check if exdb with the same name already exists
	exDbExists, err := d.db.CheckIfExDbExists(ctx, newExDb.ExDbName)
	if err != nil {
		return false, err
	}
	if exDbExists {
		return true, nil
	}
	// ExDb does not already exist, insert into database
	exDbParams := database.AddExerciseDbParams{
		Exdbname: newExDb.ExDbName,
		Org:      admin.Organization,
		Url:      newExDb.Url,
		SignKey:  newExDb.SignKey,
		AuthKey:  newExDb.AuthKey,
		Tls:      newExDb.TLS,
	}
	if err := d.db.AddExerciseDb(ctx, exDbParams); err != nil {
		return false, err
	}

	// Add the exdb as a new exercise object under its organization in casbin
	obj := fmt.Sprintf("exdb::%s", newExDb.ExDbName)
	objGroup := fmt.Sprintf("exdbs::%s", admin.Organization)
	if _, err := d.enforcer.AddNamedGroupingPolicy("g2", obj, objGroup); err != nil {
		return false, err
	}

	return false, nil
}
