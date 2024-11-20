package daemon

import (
	"context"
	"net/http"
	"strconv"
	"time"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (d *daemon) eventLabsSubrouter(r *gin.RouterGroup) {
	labs := r.Group("/labs")

	labs.Use(d.eventAuthMiddleware())
	labs.POST("", d.configureLab)
	labs.PATCH("/extend", d.extendLabExpiry)
	labs.PUT("/resetvm/:connectionIdentifier", d.resetVm)
	labs.GET("", d.getLabInfo)
	labs.GET("/hosts", d.getHostsInLab)
	labs.GET("/vpnconf/:id", d.getVpnConf)
	labs.GET("/resetlab", d.resetLab)
	labs.DELETE("/close", d.closeLab)

	queue := labs.Group("/queue")
	queue.Use(d.eventAuthMiddleware())
	queue.DELETE("/cancel", d.cancelLabConfigurationRequest)
}

type LabRequest struct {
	IsVpn bool `json:"isVpn"`
}

type LabResponse struct {
	ParentAgent ParentAgent `json:"parentAgent,omitempty"`
	Lab         Lab         `json:"labInfo,omitempty"`
}

type Lab struct {
	Tag             string                    `json:"tag"`
	EventTag        string                    `json:"eventTag"`
	ExercisesStatus map[string]ExerciseStatus `json:"exercisesStatus"`
	IsVpn           bool                      `json:"isVpn"`
	GuacCreds       *aproto.GuacCreds         `json:"guacCreds"`
	ExpiresAtTime   time.Time                 `json:"expiresAtTime,omitempty"`
}

type ExerciseStatus struct {
	Tag            string    `json:"tag"`
	ChildExercises []string  `json:"childExercises"`
	Machines       []Machine `json:"machines"`
}

type Machine struct {
	Id     string `json:"id"`
	Status string `json:"status"`
}

// Used by teams who have not yet configured their lab lab (advanced events only)
func (d *daemon) configureLab(c *gin.Context) {
	ctx := context.Background()
	var req LabRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}

	teamClaims := unpackTeamClaims(c)

	event, err := d.eventpool.GetEvent(teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("error getting event from eventpool")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}

	if event.IsMaxLabsReached() {
		c.JSON(http.StatusForbidden, APIResponse{Status: "max labs reached for event"})
		return
	}

	if event.Config.Type == int32(TypeBeginner) && req.IsVpn {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "vpn labs cannot be created for beginner events"})
		return
	}

	team, err := event.GetTeam(teamClaims.Username)
	if err != nil {
		log.Error().Err(err).Msg("Error getting team from event")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Internal server error"})
		return
	}

	if team.Lab != nil {
		log.Warn().Msg("Team has already configured a lab")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Already configured"})
		return
	}

	if team.Status == InQueue || team.Status == WaitingForLab {
		log.Warn().Msg("Team is currently waiting for lab, cannot create lab at this time")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "lab is already being created"})
		return
	}

	if err := d.agentPool.createLabForEvent(ctx, req.IsVpn, event, d.eventpool); err != nil {
		log.Error().Err(err).Msg("Error creating lab")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error when creating lab, please try again..."})
		return
	}

	//Add team to queue
	if req.IsVpn {
		team.Status = InQueue
		// Make all teams aware that event has reached maximum lab capacity
		if event.IsMaxLabsReached() {
			broadCastCommandToEventTeams(event, updateEventInfo)
		}
		log.Info().Str("username", team.Username).Msg("putting team into queue for vpn lab")
		queueElement := event.TeamsWaitingForVpnLabs.PushBack(team)
		team.QueueElement = queueElement
		sendCommandToTeam(team, updateTeam)
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	team.Status = InQueue
	if event.IsMaxLabsReached() {
		broadCastCommandToEventTeams(event, updateEventInfo)
	}
	log.Info().Str("username", team.Username).Msg("putting team into queue for browser lab")
	queueElement := event.TeamsWaitingForBrowserLabs.PushBack(team)
	team.QueueElement = queueElement
	sendCommandToTeam(team, updateTeam)
	c.JSON(http.StatusOK, APIResponse{Status: "OK"})
}

// Gets lab info for the requesting team
func (d *daemon) getLabInfo(c *gin.Context) {
	teamClaims := unpackTeamClaims(c)

	event, err := d.eventpool.GetEvent(teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("could not find event in event pool")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "event for team is not currently running"})
		return
	}

	team, err := event.GetTeam(teamClaims.Username)
	if err != nil {
		log.Error().Err(err).Msg("could not find team for event")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "could not find team for event"})
		return
	}

	if team.Lab == nil {
		log.Debug().Str("team", team.Username).Msg("no lab configured for team or team still in queue")
		c.JSON(http.StatusNotFound, APIResponse{Status: "lab not found"})
		return
	}
	labResponse := assembleLabResponse(team.Lab)

	c.JSON(http.StatusOK, APIResponse{Status: "OK", TeamLab: labResponse})
}

// Closes the lab for the requesting team
func (d *daemon) closeLab(c *gin.Context) {
	teamClaims := unpackTeamClaims(c)

	event, err := d.eventpool.GetEvent(teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("could not find event in event pool")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "event for team is not currently running"})
		return
	}

	team, err := event.GetTeam(teamClaims.Username)
	if err != nil {
		log.Error().Err(err).Msg("could not find team for event")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "could not find team for event"})
		return
	}

	event.M.Lock()
	log.Debug().Str("eventTag", event.Config.Tag).Msg("Lock on event, eventLabs.go: 186")
	team.M.Lock()
	log.Debug().Str("team", team.Username).Msg("Lock on team, eventLabs.go: 188")
	defer func(team *Team) {
		team.M.Unlock()
		log.Debug().Str("team", team.Username).Msg("Unlock on team, eventLabs.go: 191")
		event.M.Unlock()
		log.Debug().Str("eventTag", event.Config.Tag).Msg("Unlock on event, eventLabs.go: 193")
	}(team)

	if team.Lab == nil {
		log.Debug().Str("team", team.Username).Msg("lab not found for team")
		c.JSON(http.StatusNotFound, APIResponse{Status: "lab not found"})
		return
	}

	defer saveState(d.eventpool, d.conf.StatePath)

	delete(event.Labs, team.Lab.LabInfo.Tag)

	if team.Lab.Conn != nil {
		go func(team *Team) {
			if err := team.Lab.close(); err != nil {
				log.Error().Err(err).Str("team", team.Username).Msg("Error closing lab for team")
			}
		}(team)
	}
	team.Lab = nil
	sendCommandToTeam(team, updateTeam)

	c.JSON(http.StatusOK, APIResponse{Status: "OK"})
}

func (d *daemon) cancelLabConfigurationRequest(c *gin.Context) {
	teamClaims := unpackTeamClaims(c)

	event, err := d.eventpool.GetEvent(teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("could not find event in event pool")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "event for team is not currently running"})
		return
	}

	team, err := event.GetTeam(teamClaims.Username)
	if err != nil {
		log.Error().Err(err).Msg("could not find team for event")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "could not find team for event"})
		return
	}

	team.M.Lock()
	log.Debug().Str("team", team.Username).Msg("Lock on team, eventLabs.go: 234")
	defer func(team *Team) {
		team.M.Unlock()
		log.Debug().Str("team", team.Username).Msg("Unlock on team, eventLabs.go: 237")
	}(team)

	if team.Status == InQueue {
		team.Status = Idle
		if team.QueueElement != nil {
			event.TeamsWaitingForBrowserLabs.Remove(team.QueueElement)
			event.TeamsWaitingForVpnLabs.Remove(team.QueueElement)
		}
		sendCommandToTeam(team, updateTeam)
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}

	c.JSON(http.StatusBadRequest, APIResponse{Status: "team is not in queue"})
}

// Returns current hosts running in their lab
// It is returned as a list of string in format "<IP> \t <DNS>"
func (d *daemon) getHostsInLab(c *gin.Context) {
	teamClaims := unpackTeamClaims(c)

	event, err := d.eventpool.GetEvent(teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("could not find event in event pool")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "event for team is not currently running"})
		return
	}

	team, err := event.GetTeam(teamClaims.Username)
	if err != nil {
		log.Error().Err(err).Msg("could not find team for event")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "could not find team for event"})
		return
	}

	if team.Lab == nil {
		log.Debug().Str("team", team.Username).Msg("lab not found for team")
		c.JSON(http.StatusNotFound, APIResponse{Status: "lab not found"})
		return
	}

	if team.Lab.Conn != nil {
		ctx := context.Background()
		agentClient := aproto.NewAgentClient(team.Lab.Conn)
		agentReq := &aproto.GetHostsRequest{
			LabTag: team.Lab.LabInfo.Tag,
		}
		agentResp, err := agentClient.GetHostsInLab(ctx, agentReq)
		if err != nil {
			log.Error().Err(err).Msg("error getting labhosts")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK", LabHosts: agentResp.Hosts})
		return
	}
	log.Error().Msg("error getting hosts in lab: lab conn is nil")
	c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
}

// Returns the vpn config specified by index in the url
func (d *daemon) getVpnConf(c *gin.Context) {
	teamClaims := unpackTeamClaims(c)

	event, err := d.eventpool.GetEvent(teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("could not find event in event pool")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "event for team is not currently running"})
		return
	}

	team, err := event.GetTeam(teamClaims.Username)
	if err != nil {
		log.Error().Err(err).Msg("could not find team for event")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "could not find team for event"})
		return
	}

	if team.Lab == nil {
		log.Debug().Str("team", team.Username).Msg("lab not found for team")
		c.JSON(http.StatusNotFound, APIResponse{Status: "lab not found"})
		return
	}

	if !team.Lab.LabInfo.IsVPN {
		log.Debug().Str("team", team.Username).Msg("cannot download vpn conf for browser lab")
		c.JSON(http.StatusNotFound, APIResponse{Status: "cannot download vpn conf for browser lab"})
		return
	}

	vpnConfId, _ := strconv.Atoi(c.Param("id"))
	if vpnConfId >= 0 && vpnConfId < len(team.Lab.LabInfo.VpnConfs) {
		c.JSON(http.StatusOK, APIResponse{Status: "OK", Message: team.Lab.LabInfo.VpnConfs[vpnConfId]})
	} else {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "vpnconf with that id does not exist"})
	}

}

// Extends time remaining in lab by an integer amount
// specified in the config. The amount is in minutes
func (d *daemon) extendLabExpiry(c *gin.Context) {
	teamClaims := unpackTeamClaims(c)

	event, err := d.eventpool.GetEvent(teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("could not find event in event pool")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "event for team is not currently running"})
		return
	}

	team, err := event.GetTeam(teamClaims.Username)
	if err != nil {
		log.Error().Err(err).Msg("could not find team for event")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "could not find team for event"})
		return
	}

	if team.Lab == nil {
		log.Debug().Str("team", team.Username).Msg("lab not found for team")
		c.JSON(http.StatusNotFound, APIResponse{Status: "lab not found"})
		return
	}
	log.Debug().Time("time of expiry", team.Lab.ExpiresAtTime).Dur("Time left", team.Lab.ExpiresAtTime.Sub(time.Now())).Msg("Current lab times")
	if team.Lab.ExpiresAtTime.Sub(time.Now()) < 1*time.Hour {
		team.ExtendLabExpiry(d.conf.LabExpiryExtension)
		sendCommandToTeam(team, updateTeam)
		log.Debug().Time("time of expiry", team.Lab.ExpiresAtTime).Dur("Time left", team.Lab.ExpiresAtTime.Sub(time.Now())).Msg("New lab times after extend")
		saveState(d.eventpool, d.conf.StatePath)
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	} else {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "you still have more than an hour left in your lab"})
		return
	}
}

// Can be used by teams to completely reset their lab
func (d *daemon) resetLab(c *gin.Context) {

}

// Resets the connected VM in a teams lab in case of problems like freezing etc.
func (d *daemon) resetVm(c *gin.Context) {
	teamClaims := unpackTeamClaims(c)

	event, err := d.eventpool.GetEvent(teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("could not find event in event pool")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "event for team is not currently running"})
		return
	}

	team, err := event.GetTeam(teamClaims.Username)
	if err != nil {
		log.Error().Err(err).Msg("could not find team for event")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "could not find team for event"})
		return
	}

	if team.Lab == nil {
		log.Debug().Str("team", team.Username).Msg("lab not found for team")
		c.JSON(http.StatusNotFound, APIResponse{Status: "lab not found"})
		return
	}

	team.M.Lock()
	log.Debug().Str("team", team.Username).Msg("Lock on team, eventLabs.go: 408")
	team.Status = RunningVmCommand
	defer func(team *Team) {
		team.Status = Idle
		team.M.Unlock()
		log.Debug().Str("team", team.Username).Msg("Unlock on team, eventLabs.go: 413")
		sendCommandToTeam(team, updateTeam)
	}(team)
	sendCommandToTeam(team, updateTeam)

	time.Sleep(200 * time.Millisecond) // Purely for usability on the frontend

	if team.Lab.Conn != nil {
		ctx := context.Background()
		agentClient := aproto.NewAgentClient(team.Lab.Conn)
		agentReq := &aproto.VmRequest{
			LabTag:               team.Lab.LabInfo.Tag,
			ConnectionIdentifier: c.Param("connectionIdentifier"),
		}
		_, err := agentClient.ResetVmInLab(ctx, agentReq)
		if err != nil {
			log.Error().Err(err).Msg("error resetting vm")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	log.Error().Msg("error getting hosts in lab: lab conn is nil")
	c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
}

// Converts *AgentLab to LabResponse
// This is done because we cannot redact flags etc.
// from the *AgentLab type without overwriting important
// data used internally by the daemon
func assembleLabResponse(teamLab *AgentLab) *LabResponse {
	exercisesStatus := make(map[string]ExerciseStatus)
	for _, exercise := range teamLab.LabInfo.Exercises {
		var childExercises []string
		for _, childExercise := range exercise.ChildExercises {
			childExercises = append(childExercises, childExercise.Tag)
		}
		var machines []Machine
		for _, machine := range exercise.Machines {
			machines = append(machines, Machine{
				Id:     machine.Id,
				Status: machine.Status,
			})
		}
		exercisesStatus[exercise.Tag] = ExerciseStatus{
			Tag:            exercise.Tag,
			ChildExercises: childExercises,
			Machines:       machines,
		}
	}
	labResponse := &LabResponse{
		ParentAgent: teamLab.ParentAgent,
		Lab: Lab{
			Tag:             teamLab.LabInfo.Tag,
			EventTag:        teamLab.LabInfo.EventTag,
			ExercisesStatus: exercisesStatus,
			IsVpn:           teamLab.LabInfo.IsVPN,
			GuacCreds:       teamLab.LabInfo.GuacCreds,
			ExpiresAtTime:   teamLab.ExpiresAtTime,
		},
	}
	return labResponse
}
