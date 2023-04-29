package daemon

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (d *daemon) adminEventTeamsSubrouter(r *gin.RouterGroup) {
	teams := r.Group("/teams")

	teams.Use(d.adminAuthMiddleware())
	// CRUD

	teams.GET("/:eventTag", d.getTeams)
	teams.DELETE("/:teamname", d.deleteTeam)

	// Additional routes
	teams.PUT("", d.updateTeam)
}

func (d *daemon) getTeams(c *gin.Context) {
	type GetTeamsResponse struct {
		Tag        string
		Email      string
		Username   string
		Status     string
		CreatedAt  time.Time
		LastAccess time.Time
	}

	ctx := context.Background()

	eventTag := c.Param("eventTag")

	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("EventTag", eventTag).
		Msg("AdminUser is trying to get teams for event")

	dbEvent, err := d.db.GetEventByTag(ctx, eventTag)
	if err != nil {
		log.Error().Err(err).Msg("error getting event from event pool")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}

	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, "events::Admins", "read"},
		{admin.Username, admin.Organization, fmt.Sprintf("events::%s", dbEvent.Organization), "read"},
		{admin.Username, admin.Organization, fmt.Sprintf("notOwnedEvents::%s", dbEvent.Organization), "read"},
	}

	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[0] || authorized[1] || err != nil {
		if !authorized[2] {
			if dbEvent.Createdby != admin.Username {
				c.JSON(http.StatusForbidden, gin.H{"status": "Forbidden"})
				return
			}
		}

		event, _ := d.eventpool.GetEvent(eventTag) // Only to get team status

		dbTeams, err := d.db.GetTeamsForEvent(ctx, dbEvent.ID)
		if err != nil {
			log.Error().Err(err).Msg("error getting teams for event")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
			return
		}

		teams := []GetTeamsResponse{}
		for _, dbTeam := range dbTeams {
			teamStatus := "N/A"
			if event != nil {
				poolTeam, _ := event.GetTeam(dbTeam.Username)
				if poolTeam != nil {
					teamStatus = poolTeam.Status.String()
				}
			}

			team := GetTeamsResponse{
				Tag:        dbTeam.Tag,
				Email:      dbTeam.Email,
				Username:   dbTeam.Username,
				Status:     teamStatus,
				CreatedAt:  dbTeam.CreatedAt,
				LastAccess: dbTeam.LastAccess.Time,
			}
			teams = append(teams, team)
		}
		c.JSON(http.StatusOK, gin.H{
			"status": "OK",
			"teams":  teams,
		})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) deleteTeam(c *gin.Context) {

}

func (d *daemon) updateTeam(c *gin.Context) {

}
