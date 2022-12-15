package daemon

import (
	"context"
	"fmt"
	"net/http"
	"time"

	eproto "github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type EventRequest struct {
	Type               uint8     `json:"type" binding:"required"`
	Name               string    `json:"name" binding:"required"`
	Tag                string    `json:"tag" binding:"required"`
	InitialLabs        uint      `json:"initialLabs,omitempty"`
	MaxLabs            uint      `json:"maxLabs" binding:"required"`
	Frontend           string    `json:"frontend" binding:"required"`
	ExerciseTags       []string  `json:"exerciseTags" binding:"required"`
	ExpectedFinishDate time.Time `json:"expectedFinishDate" binding:"required"`
	SecretKey          string    `json:"secretKey,omitempty"`
}

func (d *daemon) eventSubrouter(r *gin.RouterGroup) {
	events := r.Group("/events")

	events.Use(d.adminAuthMiddleware())
	// CRUD
	events.POST("/", d.newEvent)
	events.GET("/", d.getEvents)

	// Additional routes
	events.POST("/exercise/add", d.addExerciseToEvent)
	events.POST("/exercise/reset", d.resetExerciseInEvent)
}

func (d *daemon) newEvent(c *gin.Context) {
	ctx := context.Background()
	var req EventRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error parsing request"})
		return
	}

	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("NewEventTag", req.Tag).
		Msg("AdminUser is trying to create a event")

	log.Debug().Msgf("new event request: %v", req)
	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, fmt.Sprintf("events::%s", admin.Organization), "write"},
		{admin.Username, admin.Organization, fmt.Sprintf("secretchals::%s", admin.Organization), "write"},
	}
	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[0] || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing user creation")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		// TODO Check user quota

		uniqueExercisesList := removeDuplicates(req.ExerciseTags)

		exClientResp, err := d.exClient.GetExerciseByTags(ctx, &eproto.GetExerciseByTagsRequest{Tag: uniqueExercisesList})
		if err != nil {
			log.Error().Err(err).Msg("error while retrieving exercises by tags")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		for _, exercise := range exClientResp.Exercises {
			if exercise.Secret && !authorized[1] {
				log.Warn().Msg("admin user without secret rights tried creating an event with secret challenges")
				c.JSON(http.StatusUnauthorized, APIResponse{Status: "unauthorized"})
				return
			}
		}

	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) getEvents(c *gin.Context) {

}

func (d *daemon) addExerciseToEvent(c *gin.Context) {

}

func (d *daemon) resetExerciseInEvent(c *gin.Context) {

}

// removeDuplicates removes duplicated values in given list
// used incoming CreateEventRequest
func removeDuplicates(exercises []string) []string {
	k := make(map[string]bool)
	var uniqueExercises []string

	for _, e := range exercises {
		if _, v := k[e]; !v {
			k[e] = true
			uniqueExercises = append(uniqueExercises, e)
		}
	}
	return uniqueExercises
}
