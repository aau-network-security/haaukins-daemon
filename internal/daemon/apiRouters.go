package daemon

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (d *daemon) adminSubrouter(r *gin.RouterGroup) {
	d.adminUserSubrouter(r)
	d.adminOrgSubrouter(r)
	d.adminAgentsSubrouter(r)
	d.adminEventSubrouter(r)
	d.adminExerciseSubrouter(r)
}

func (d *daemon) eventSubrouter(r *gin.RouterGroup) {
	d.eventTeamSubrouter(r)
	d.eventLabsSubrouter(r)
	d.eventExercisesSubrouter(r)

	r.GET("/:eventTag", d.getEventInfo)
}

type EventInfoResponse struct {
	Tag              string `json:"tag"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	Secret           bool   `json:"secret"`
	PublicScoreboard bool   `json:"publicScoreboard"`
	TeamSize         int32  `json:"teamSize"`
}

func (d *daemon) getEventInfo(c *gin.Context) {
	eventTag := c.Param("eventTag")

	event, err := d.eventpool.GetEvent(eventTag)
	if err != nil {
		log.Error().Err(err).Msg("error getting event from event pool")
		c.JSON(http.StatusNotFound, APIResponse{Status: "event not found"})
		return
	}
	secret := false
	if event.Config.SecretKey != "" {
		secret = true
	}
	eventInfoResponse := &EventInfoResponse{
		Tag:              event.Config.Tag,
		Name:             event.Config.Name,
		Type:             EventType(event.Config.Type).String(),
		PublicScoreboard: event.Config.PublicScoreBoard,
		Secret:           secret,
		TeamSize:         event.Config.TeamSize,
	}

	c.JSON(http.StatusOK, APIResponse{Status: "OK", EventInfo: eventInfoResponse})
}
