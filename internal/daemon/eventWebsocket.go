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
	updateEventInfo  = "updateEventInfo"
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
			if websocket.IsUnexpectedCloseError(err, websocket.CloseAbnormalClosure) {
				log.Error().Err(err).Msg("error reading json from websocket connection")
			}
			return
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
		team.M.Lock()
		if team.ActiveWebsocketConnections == nil {
			team.ActiveWebsocketConnections = make(map[string]*websocket.Conn)
		}
		team.ActiveWebsocketConnections[wsId] = ws
		team.M.Unlock()

		defer func(ws *websocket.Conn, team *Team, wsId string) {
			log.Debug().Msg("closing connection")
			team.M.Lock()
			delete(team.ActiveWebsocketConnections, wsId)
			team.M.Unlock()
			ws.Close()
		}(ws, team, wsId)

		for {
			if err = ws.WriteMessage(mt, []byte("hb")); err != nil {
				log.Debug().Msg("client disconnected")
				return
			}
			time.Sleep(5 * time.Second)
		}
	}
}

func sendCommandToTeam(team *Team, command string) {
	for _, ws := range team.ActiveWebsocketConnections {
		ws.WriteMessage(websocket.TextMessage, []byte(command))
	}
}

func broadCastCommandToEventTeams(event *Event, command string) {
	for _, team := range event.Teams {
		sendCommandToTeam(team, command)
	}
}
