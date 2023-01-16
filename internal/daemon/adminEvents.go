package daemon

import (
	"container/list"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/db"
	eproto "github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

const (
	StatusRunning int32 = iota
	StatusSuspended
	StatusClosed
)

// func (status int32) String() string {
// 	switch status {
//     case StatusRunning:
//         return "running"
//     case StatusSuspended:
//         return "suspended"
//     case StatusClosed:
//         return "closed"
//     default:
//         return "unknown"
//     }
// }

const (
	displayTimeFormat        = "2006-01-02 15:04:05"
	averageContainerMemUsage = 50  // MB found from running a lab with alot of containers and taking the average mem usage
	labBaseMemoryUsage       = 100 // In MB all labs have a DHCP and DNS container running
	vmAvrMemoryUsage         = 3072
)

func (d *daemon) adminEventSubrouter(r *gin.RouterGroup) {
	events := r.Group("/events")

	events.Use(d.adminAuthMiddleware())
	// CRUD
	events.POST("", d.newEvent)
	events.GET("", d.getEvents)
	events.GET("/bystatus/:status", d.getEvents)
	events.DELETE("/:eventTag", d.deleteEvent)

	// Additional routes
	events.PUT("/close/:eventTag", d.closeEvent)
	events.POST("/exercise/add", d.addExerciseToEvent)
	events.POST("/exercise/reset", d.resetExerciseInEvent)
}

// Creates a new event, including environments on all available connected agents
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
			log.Error().Err(err).Msgf("Encountered an error while authorizing event creation")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		// TODO Check user quota
		// TODO Check if initial labs is less or equal than maxlabs

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
				c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
				return
			}
		}

		// only calculate if beginner event, as the resources are spun up from the beginning
		estimatedMemUsage, estimatedMemUsagePerLab := calculateEstimatedEventMemUsage(exClientResp.Exercises, req.TeamSize, req.MaxLabs, EventType(req.Type))

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

		var estimatedMemSpent uint64 // Current resources spent on running labs
		for _, event := range d.eventpool.Events {
			estimatedMemSpent += event.EstimatedMemoryUsage
		}

		resourceEstimates := ResourceEstimates{
			EstimatedMemUsage:       estimatedMemUsage,
			EstimatedMemUsagePerLab: estimatedMemUsagePerLab,
			EstimatedMemorySpent:    estimatedMemSpent,
		}

		if err := d.agentPool.createNewEnvOnAvailableAgents(ctx, d.eventpool, req, resourceEstimates); err != nil {
			if err == AllAgentsReturnedErr {
				log.Error().Err(AllAgentsReturnedErr).Msg("error creating environments on all agents")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error... Agents may be out of resources"})
				return
			} else if err == NoAgentsConnected {
				log.Error().Err(NoAgentsConnected).Msg("error creating environments on all agents")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error: no agents connected... contact superadmin"})
				return
			} else if err == NoResourcesError {
				log.Error().Err(NoResourcesError).Msg("error creating environments on all agents")
				c.JSON(http.StatusBadRequest, APIResponse{Status: "not enough resources available for desired event"})
				return
			}
		}

		eventToAdd := db.AddEventParams{
			Tag:                   req.Tag,
			Type:                  req.Type,
			Name:                  req.Name,
			Organization:          admin.Organization,
			InitialLabs:           req.InitialLabs,
			MaxLabs:               req.MaxLabs,
			Frontend:              req.VmName,
			Status:                StatusRunning,
			Exercises:             strings.Join(req.ExerciseTags, ","),
			DynamicScoring:        req.DynamicScoring,
			DynamicMax:            req.DynamicMax,
			DynamicMin:            req.DynamicMin,
			DynamicSolveThreshold: req.DynamicSolveThreshold,
			StartedAt:             time.Now(),
			FinishExpected:        req.ExpectedFinishDate,
			Createdby:             admin.Username,
			Secretkey:             req.SecretKey,
		}

		if err := d.db.AddEvent(ctx, eventToAdd); err != nil {
			log.Error().Err(err).Msg("error adding event to database")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
			if err := d.agentPool.closeEnvironmentOnAllAgents(ctx, req.Tag); err != nil {
				log.Error().Err(err).Msg("error closing environment on all agents")
			}
			return
		}

		event := &Event{
			Config:                     req,
			Teams:                      make(map[string]*Team),
			Labs:                       make(map[string]*AgentLab),
			UnassignedBrowserLabs:      make(chan *AgentLab, req.MaxLabs),
			TeamsWaitingForBrowserLabs: list.New(),
			UnassignedVpnLabs:          make(chan *AgentLab, req.MaxLabs),
			TeamsWaitingForVpnLabs:     list.New(),
			EstimatedMemoryUsage:       estimatedMemUsage,
			EstimatedMemoryUsagePerLab: estimatedMemUsagePerLab,
		}
		d.eventpool.AddEvent(event)

		event.startQueueHandlers(d.eventpool, d.conf.StatePath)

		saveState(d.eventpool, d.conf.StatePath)

		// Since environment successfully
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// Lists all events based on permissions from Casbin.
// If bystatus route is used, it will only return events with a specific status
func (d *daemon) getEvents(c *gin.Context) {
	ctx := context.Background()

	statusParam := c.Param("status")
	var status int64
	var err error
	if statusParam != "" {
		status, err = strconv.ParseInt(statusParam, 10, 32)
		if err != nil {
			log.Error().Err(err).Msg("error parsing url parameter for get events")
			c.JSON(http.StatusBadRequest, APIResponse{Status: "Bad Request"})
			return
		}
	}

	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Int32("Status", int32(status)).
		Msg("AdminUser is trying to list events")

	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, "events::Admins", "read"},
		{admin.Username, admin.Organization, fmt.Sprintf("events::%s", admin.Organization), "read"},
		{admin.Username, admin.Organization, fmt.Sprintf("notOwnedEvents::%s", admin.Organization), "read"},
	}
	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[1] || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing list events")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		if statusParam != "" {
			if authorized[0] {
				events, err := d.db.GetEventsByStatus(ctx, int32(status))
				if err != nil {
					log.Error().Err(err).Msg("error getting events from database")
					c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
					return
				}
				c.JSON(http.StatusOK, APIResponse{Status: "OK", Events: events})
				return
			} else if authorized[2] { // Admin is allowed to list events not created by themselves
				getEventsParam := db.GetOrgEventsByStatusParams{
					Organization: admin.Organization,
					Status:       int32(status),
				}
				events, err := d.db.GetOrgEventsByStatus(ctx, getEventsParam)
				if err != nil {
					log.Error().Err(err).Msg("error getting events from database")
					c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
					return
				}
				c.JSON(http.StatusOK, APIResponse{Status: "OK", Events: events})
				return
			}
			getOrgParams := db.GetOrgEventsByStatusAndCreatedByParams{
				Organization: admin.Organization,
				Createdby:    admin.Username,
				Status:       int32(status),
			}
			events, err := d.db.GetOrgEventsByStatusAndCreatedBy(ctx, getOrgParams)
			if err != nil {
				log.Error().Err(err).Msg("error getting events from database")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
				return
			}
			c.JSON(http.StatusOK, APIResponse{Status: "OK", Events: events})
			return
		}
		if authorized[0] {
			events, err := d.db.GetAllEvents(ctx)
			if err != nil {
				log.Error().Err(err).Msg("error getting events from database")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
				return
			}
			c.JSON(http.StatusOK, APIResponse{Status: "OK", Events: events})
			return
		} else if authorized[2] { // Admin is allowed to list events not created by themselves
			events, err := d.db.GetOrgEvents(ctx, admin.Organization)
			if err != nil {
				log.Error().Err(err).Msg("error getting events from database")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
				return
			}
			c.JSON(http.StatusOK, APIResponse{Status: "OK", Events: events})
			return
		}
		getOrgParams := db.GetOrgEventsByCreatedByParams{
			Organization: admin.Organization,
			Createdby:    admin.Username,
		}
		events, err := d.db.GetOrgEventsByCreatedBy(ctx, getOrgParams)
		if err != nil {
			log.Error().Err(err).Msg("error getting events from database")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK", Events: events})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// Deletes an event including its related teams from the database
// Teams are referenced to the event_id by cascade delete in postgres
func (d *daemon) deleteEvent(c *gin.Context) {
	ctx := context.Background()

	eventTag := c.Param("eventTag")
	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("EventTag", eventTag).
		Msg("AdminUser is trying to stop an event")
	event, err := d.db.GetEventByTag(ctx, eventTag)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, APIResponse{Status: "event not found in the database"})
			return
		}
		log.Error().Err(err).Msg("error getting event from db")
	}
	if event.Status != StatusClosed {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "close event before deleting it"})
		return
	}

	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, fmt.Sprintf("events::%s", event.Organization), "write"},
		{admin.Username, admin.Organization, fmt.Sprintf("notOwnedEvents::%s", event.Organization), "write"},
	}
	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[0] || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing event deletion")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		if !authorized[1] && admin.Username != event.Createdby {
			log.Warn().Str("username", admin.Username).Msg("admin tried to delete an event not created by themselves")
			c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
			return
		}

		if err := d.db.DeleteEventByTag(ctx, event.Tag); err != nil {
			log.Error().Err(err).Msg("error deleting event from database")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
			return
		}

		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// Changes the event status to closed in the database, and assigns a new tag which includes
// the unix timestamp for when the event was closed
// It also closes all releated environments on all agents
func (d *daemon) closeEvent(c *gin.Context) {
	ctx := context.Background()

	eventTag := c.Param("eventTag")
	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("EventTag", eventTag).
		Msg("AdminUser is trying to stop an event")
	event, err := d.db.GetEventByTag(ctx, eventTag)
	if err != nil {
		log.Error().Err(err).Msg("error getting event from db")
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, APIResponse{Status: "event not found in the database"})
			return
		}
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}

	if event.Status == StatusClosed {
		log.Warn().Msg("admin user tried to close already closed event")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "event already closed"})
		return
	}

	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, fmt.Sprintf("events::%s", event.Organization), "write"},
		{admin.Username, admin.Organization, fmt.Sprintf("notOwnedEvents::%s", event.Organization), "write"},
	}
	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[0] || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing event closure")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		if !authorized[1] && admin.Username != event.Createdby {
			log.Warn().Str("username", admin.Username).Msg("admin tried to stop an event not created by themselves")
			c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
			return
		}

		if err := d.agentPool.closeEnvironmentOnAllAgents(ctx, event.Tag); err != nil {
			log.Error().Err(err).Msg("error closing environments on agents")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
			return
		}

		newEventTag := event.Tag + "-" + strconv.Itoa(int(time.Now().Unix()))
		closeEventParams := db.CloseEventParams{
			Newtag: newEventTag,
			Oldtag: event.Tag,
			Finishedat: sql.NullTime{
				Time:  time.Now(),
				Valid: true,
			},
			Newstatus: StatusClosed,
		}

		if err := d.db.CloseEvent(ctx, closeEventParams); err != nil {
			log.Error().Err(err).Msg("error updating event db status to closed")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
			return
		}

		if err := d.eventpool.RemoveEvent(event.Tag); err != nil {
			log.Warn().Msg("event not found in event pool, something else has removed")
		}

		saveState(d.eventpool, d.conf.StatePath)
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// TODO addExerciseToEvent
// Is used to add exercises to events on the fly while the event is running
func (d *daemon) addExerciseToEvent(c *gin.Context) {

}

// TODO resetExerciseInEvent
// Resets an exercise for a user in a specific event
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

// TODO add calculation for advanced events as well
func calculateEstimatedEventMemUsage(exercises []*eproto.Exercise, teamSize, maxLabs int32, eventType EventType) (uint64, uint64) {
	vmCountPerLab := int(teamSize)

	containerCountPerLab := 0
	if eventType == TypeBeginner {
		for _, exercise := range exercises {
			for _ = range exercise.Instance {
				containerCountPerLab += 1
			}
		}
	} else {
		containerCountPerLab = 5 // Advanced labs can have max 5 exercises running at a time
	}

	estimatedMemUsagePerLab := uint64(vmCountPerLab)*(vmAvrMemoryUsage*1000000) + uint64(containerCountPerLab)*averageContainerMemUsage*1000000 + uint64(labBaseMemoryUsage)*1000000

	log.Debug().Uint64("estimatedMemUsagePerLab", estimatedMemUsagePerLab).Int("vmCountPerLab", vmCountPerLab).Int("containerCountPerLab", containerCountPerLab).Msg("Calculated amount of virtual instances per lab")
	// VMs idle at little over 2 gigs of ram and maximum 4 gigs of usage
	// So assuming average consumption will be somewhere in the middle
	estimatedMemUsage := estimatedMemUsagePerLab * uint64(maxLabs)
	log.Debug().Uint64("estimatedMemUsage", estimatedMemUsage).Msg("estimated memory usage for event")

	return estimatedMemUsage, estimatedMemUsagePerLab
}
