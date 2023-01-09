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
	Idle
)

func (d *daemon) eventLabsSubrouter(r *gin.RouterGroup) {
	labs := r.Group("/labs")

	labs.Use(d.eventAuthMiddleware())
	labs.POST("/", d.configureLab)
	labs.GET("/", d.getLab)
	labs.GET("/resetlab", d.resetLab)
	labs.GET("/resetvm", d.resetVm)
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

	if err := d.agentPool.createLabForEvent(ctx, req.IsVpn, event.Config.Tag); err != nil {
		log.Error().Err(err).Msg("Error creating lab")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "error when creating lab, please try again..."})
		return
	}

	// Add to queue
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
func (d *daemon) getLab(c *gin.Context) {

}

// Can be used by teams to completely reset their lab
func (d *daemon) resetLab(c *gin.Context) {

}

// Resets the connected VM in a teams lab in case of problems like freezing etc.
func (d *daemon) resetVm(c *gin.Context) {

}
