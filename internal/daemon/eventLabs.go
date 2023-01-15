package daemon

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type LabRequest struct {
	IsVpn bool `json:"isVpn"`
}

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
		go func() {
			defer func() {
				if recover() != nil {
					log.Debug().Msg("channel closed while sending team to queue")
				}
			}()
			team.Status = InQueue
			log.Info().Str("username", team.Username).Msg("putting team into queue for vpn lab")
			event.TeamsWaitingForVpnLabs <- team
			log.Info().Str("username", team.Username).Msg("team got taken out of vpn queue, exiting go routine")
		}()
		return
	}
	go func() {
		defer func() {
			if recover() != nil {
				log.Debug().Msg("channel closed while sending team to queue")
			}
		}()
		team.Status = InQueue
		log.Info().Str("username", team.Username).Msg("putting team into queue for vpn lab")
		event.TeamsWaitingForBrowserLabs <- team
		log.Info().Str("username", team.Username).Msg("team got taken out of vpn queue, exiting go routine")
	}()

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

	for _, exercise := range team.Lab.LabInfo.Exercises {
		for _, childExercise := range exercise.ChildExercises {
			childExercise.Flag = ""
		}
		for _, machine := range exercise.Machines {
			machine.Image = ""
			machine.Type = ""
		}
	}

	c.JSON(http.StatusOK, APIResponse{Status: "OK", TeamLab: team.Lab})
}

// Can be used by teams to completely reset their lab
func (d *daemon) resetLab(c *gin.Context) {

}

// Resets the connected VM in a teams lab in case of problems like freezing etc.
func (d *daemon) resetVm(c *gin.Context) {

}
