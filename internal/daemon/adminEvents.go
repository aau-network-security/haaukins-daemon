package daemon

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/aau-network-security/haaukins-daemon/internal/db"
	eproto "github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

const (
	displayTimeFormat       = "2006-01-02 15:04:05"
	StatusRunning     int32 = iota
	StatusSuspended
	StatusStopped
)

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

// TODO validate config
func (d *daemon) newEvent(c *gin.Context) {
	ctx := context.Background()
	var req EventConfig
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

		exists, err := d.db.CheckIfEventExist(ctx, req.Tag)
		if err != nil {
			log.Error().Err(err).Msg("error checking if event exists")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
			return
		}
		if exists {
			log.Warn().Msg("admin user tried to create an event with tag that is already in the database")
			c.JSON(http.StatusBadRequest, APIResponse{Status: fmt.Sprintf("Event with tag '%s' already exists", req.Tag)})
			return
		}

		envReq := aproto.CreatEnvRequest{
			EventTag: req.Tag,
			EnvType:  req.Type,
			// Just temporarily using hardcoded vm config
			Vm: &aproto.VmConfig{
				Image:    req.VmName,
				MemoryMB: 4096,
				Cpu:      0,
			},
			InitialLabs: req.InitialLabs,
			Exercises:   req.ExerciseTags,
			TeamSize:    req.TeamSize,
		}
		if err := d.agentPool.createNewEnvOnAvailableAgents(ctx, envReq); err != nil {
			if err == AllAgentsReturnedErr {
				log.Error().Err(AllAgentsReturnedErr).Msg("error creating environments on all agents")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
				return
			} else if err == NoAgentsConnected {
				log.Error().Err(NoAgentsConnected).Msg("error creating environments on all agents")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error: no agents connected... contact superadmin"})
				return
			}
		}

		eventToAdd := db.AddEventParams{
			Tag:          req.Tag,
			Name:         req.Name,
			Organization: admin.Organization,
			InitialLabs:  req.InitialLabs,
			MaxLabs:      req.MaxLabs,
			Frontend:     req.VmName,
			Status: sql.NullInt32{
				Int32: StatusRunning,
				Valid: true,
			},
			Exercises:      strings.Join(req.ExerciseTags, ","),
			StartedAt:      time.Now(),
			FinishExpected: req.ExpectedFinishDate,
			Createdby:      admin.Username,
			Secretkey:      req.SecretKey,
		}

		// TODO Make sure to close agent environments if db fails
		if err := d.db.AddEvent(ctx, eventToAdd); err != nil {
			log.Error().Err(err).Msg("error adding event to database")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
			if err := d.agentPool.closeEnvironmentOnAllAgents(ctx, req.Tag); err != nil {
				log.Error().Err(err).Msg("error closing environment on all agents")
			}
			return
		}

		// TODO Start goroutine to handle lab assignments
		event := &Event{
			Config:              req,
			Teams:               make(map[string]*Team),
			Labs:                make(map[string]*AgentLab),
			UnassignedLabs:      make(chan AgentLab, req.MaxLabs),
			TeamsWaitingForLabs: make(chan Team),
		}
		d.eventpool.AddEvent(event)
		// Since environment successfully
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
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
