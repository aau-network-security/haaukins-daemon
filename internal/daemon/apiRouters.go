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
	d.adminEventTeamsSubrouter(r)
}

func (d *daemon) eventSubrouter(r *gin.RouterGroup) {
	d.eventTeamSubrouter(r)
	d.eventLabsSubrouter(r)
	d.eventExercisesSubrouter(r)
	d.eventScoreSubrouter(r)
	r.GET("/:eventTag", d.getEventInfo)
	r.GET("/ws", d.eventWebsocket)
}

type EventInfoResponse struct {
	Tag              string `json:"tag"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	Secret           bool   `json:"secret"`
	PublicScoreboard bool   `json:"publicScoreboard"`
	TeamSize         int32  `json:"teamSize"`
	IsMaxLabsReached bool   `json:"isMaxLabsReached"`
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

	isMaxLabsReached := event.IsMaxLabsReached()

	eventInfoResponse := &EventInfoResponse{
		Tag:              event.Config.Tag,
		Name:             event.Config.Name,
		Type:             EventType(event.Config.Type).String(),
		PublicScoreboard: event.Config.PublicScoreBoard,
		Secret:           secret,
		TeamSize:         event.Config.TeamSize,
		IsMaxLabsReached: isMaxLabsReached,
	}

	c.JSON(http.StatusOK, APIResponse{Status: "OK", EventInfo: eventInfoResponse})
}
