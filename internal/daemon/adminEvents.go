package daemon

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/aau-network-security/haaukins-daemon/internal/agent"
	eproto "github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
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
			c.JSON(http.StatusBadRequest, APIResponse{Status: fmt.Sprintf("Event with tag \"%s\" already exists", req.Tag)})
		}

		if len(d.agentPool.Agents) > 0 {
			var m sync.Mutex
			var wg sync.WaitGroup
			var errors []error
			for _, a := range d.agentPool.Agents {
				wg.Add(1)
				go func(conf *EventConfig, a *agent.Agent) {
					defer wg.Done()
					client := aproto.NewAgentClient(a.Conn)
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
					if _, err := client.CreateEnvironment(ctx, &envReq); err != nil {
						log.Warn().Str("agentName", a.Name).Msg("error creating environment for agent")
						m.Lock()
						errors = append(errors, err)
					}
				}(&req, a)
			}
			wg.Wait()
			if len(errors) == len(d.agentPool.Agents) {
				log.Error().Msg("all agents returned error on creating environment")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
				return
			}
		} else {
			log.Warn().Msg("admin user tried to start an event without any agents connected")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "No agents to serve labs... Contact a platform administrator"})
			return
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
