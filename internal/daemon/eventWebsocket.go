package daemon

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

// Commands
const (
	updateChallenges = "updateChallenges"
	updateTeam       = "updateTeam"
)

func (d *daemon) eventWebsocket(c *gin.Context) {
	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	mt := websocket.TextMessage
	// Construct a type to hold the token
	type WsAuthRequest struct {
		Token string `json:"token"`
	}
	for {
		// read the on open message
		req := WsAuthRequest{}
		if err := ws.ReadJSON(&req); err != nil {
			log.Error().Err(err).Msg("error reading json from websocket connection")
			continue
		}
		// Validate the token
		claims, err := d.jwtValidate(nil, req.Token)
		if err != nil {
			ws.WriteMessage(mt, []byte("invalid token"))
			return
		}

		// Authorize the user
		teamName := string(claims["sub"].(string))
		eventTag := string(claims["eventTag"].(string))
		// Send agent metrics if authorized

		event, err := d.eventpool.GetEvent(eventTag)
		if err != nil {
			ws.WriteMessage(mt, []byte("invalid event"))
			return
		}

		team, err := event.GetTeam(teamName)
		if err != nil {
			ws.WriteMessage(mt, []byte("team not found for event"))
			return
		}

		wsId := uuid.New().String()
		if team.ActiveWebsocketConnections == nil {
			team.ActiveWebsocketConnections = make(map[string]*websocket.Conn)
		}
		team.ActiveWebsocketConnections[wsId] = ws

		defer func(ws *websocket.Conn, team *Team, wsId string) {
			delete(team.ActiveWebsocketConnections, wsId)
			ws.Close()
		}(ws, team, wsId)

		for {
			if err = ws.WriteMessage(mt, []byte("hb")); err != nil {
				log.Error().Err(err).Msg("error writing hb to client")
				return
			}
			time.Sleep(2 * time.Second)
		}
	}
}
