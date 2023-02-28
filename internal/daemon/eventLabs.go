package daemon

import (
	"context"
	"net/http"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type TeamStatus uint8

const (
	WaitingForLab TeamStatus = iota
	InQueue
	RunningExerciseCommand
	Idle
)

func (status TeamStatus) String() string {
	switch status {
	case WaitingForLab:
		return "waiting for lab"
	case InQueue:
		return "in lab queue"
	case RunningExerciseCommand:
		return "running exercise command"
	case Idle:
		return "idle"
	default:
		return "unknown"
	}
}

func (d *daemon) eventLabsSubrouter(r *gin.RouterGroup) {
	labs := r.Group("/labs")

	labs.Use(d.eventAuthMiddleware())
	labs.POST("", d.configureLab)
	labs.GET("", d.getLabInfo)
	labs.GET("/resetlab", d.resetLab)
	labs.GET("/resetvm", d.resetVm)
}

type LabRequest struct {
	IsVpn bool `json:"isVpn"`
}

type LabResponse struct {
	ParentAgent ParentAgent `json:"parentAgent,omitempty"`
	Lab         Lab         `json:"labInfo,omitempty"`
}

type Lab struct {
	Tag             string            `json:"tag"`
	EventTag        string            `json:"eventTag"`
	ExercisesStatus map[string]ExerciseStatus  `json:"exercisesStatus"`
	IsVpn           bool              `json:"isVpn"`
	GuacCreds       *aproto.GuacCreds `json:"guacCreds"`
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
// TODO Check if event has reached maximum number of labs for event
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
		log.Info().Str("username", team.Username).Msg("putting team into queue for vpn lab")
		queueElement := event.TeamsWaitingForVpnLabs.PushBack(team)
		team.QueueElement = queueElement
		sendCommandToTeam(team, updateTeam)
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	team.Status = InQueue
	log.Info().Str("username", team.Username).Msg("putting team into queue for vpn lab")
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

// Can be used by teams to completely reset their lab
func (d *daemon) resetLab(c *gin.Context) {

}

// Resets the connected VM in a teams lab in case of problems like freezing etc.
func (d *daemon) resetVm(c *gin.Context) {

}

func assembleLabResponse(teamLab *AgentLab) (*LabResponse) {
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
		},
	}
	return labResponse
}
