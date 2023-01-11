package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

func (d *daemon) adminAgentsSubrouter(r *gin.RouterGroup) {
	agents := r.Group("/agents")

	agents.GET("/ws/:agent", d.agentWebsocket)

	agents.Use(d.adminAuthMiddleware())

	// CRUD
	agents.POST("", d.newAgent)
	agents.GET("", d.getAgents)
	agents.PUT("", d.updateAgent)
	agents.DELETE("/:agent", d.deleteAgent)

	// Additional routes

	agents.GET("/reconnect/:agent", d.reconnectAgent)
	agents.GET("/agentstate/lock/:agent", d.lockAgentState)
	agents.GET("/agentstate/unlock/:agent", d.unlockAgentState)
}

type AgentRequest struct {
	Name    string `json:"name"`
	Url     string `json:"url,omitempty"`
	SignKey string `json:"signKey,omitempty"`
	AuthKey string `json:"authKey,omitempty"`
	Tls     bool   `json:"tls,omitempty"`
}

type AgentResponse struct {
	Name       string `json:"name"`
	Connected  bool   `json:"connected"`
	Url        string `json:"url"`
	SignKey    string `json:"signKey"`
	AuthKey    string `json:"authKey"`
	Tls        bool   `json:"tls"`
	StateLock  bool   `json:"stateLock"`
}

// Creates a new agent connection and stores connection information in the database
func (d *daemon) newAgent(c *gin.Context) {
	ctx := context.Background()
	var req AgentRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error parsing request"})
		return
	}

	// Validate all request parameters
	if err := validateRequestParams(req, true, true, true, true); err != nil {
		log.Error().Err(err).Msg("error validation request")
		c.JSON(http.StatusBadRequest, APIResponse{Status: err.Error()})
		return
	}

	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("NewAgent", req.Name).
		Msg("AdminUser is trying to create a new agent")

	sub := admin.Username
	dom := admin.Organization
	obj := "agents::Admins"
	act := "write"
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing agent creation")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		exists, err := d.db.CheckIfAgentExists(ctx, req.Name)
		if err != nil {
			log.Error().Err(err).Msgf("Error checking if agent exists")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		if exists {
			log.Error().Str("agentName", req.Name).Msg("agent with that name already exists")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "agent with that name already exists"})
			return
		}

		// Making sure the connection is okay, if yes, add to agentPool
		serviceConf := ServiceConfig{
			Grpc:       req.Url,
			AuthKey:    req.AuthKey,
			SignKey:    req.SignKey,
			TLSEnabled: req.Tls,
		}
		conn, memoryInstalled, err := NewAgentConnection(serviceConf)
		if err != nil {
			log.Error().Err(err).Msg("error connecting to new agent")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("error connecting to new agent: %v", err)})
			return
		}

		streamCtx, cancel := context.WithCancel(context.Background())
		agentForPool := &Agent{
			Name:      req.Name,
			Conn:      conn,
			StateLock: false,
			Errors:    []error{},
			Close:     cancel,
			Resources: AgentResources{
				MemoryInstalled: memoryInstalled,
			},
		}

		if err := d.agentPool.connectToStreams(streamCtx, d.newLabs, agentForPool, d.eventpool); err != nil {
			log.Error().Err(err).Msg("error connecting to agent streams")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("error connecting to agent streams: %v", err)})
			return
		}

		d.agentPool.addAgent(agentForPool)

		// Inserting the new agent into the database
		newAgentParams := db.InsertNewAgentParams{
			Name:    req.Name,
			Url:     req.Url,
			Signkey: req.SignKey,
			Authkey: req.AuthKey,
			Tls:     req.Tls,
		}
		if err := d.db.InsertNewAgent(ctx, newAgentParams); err != nil {
			log.Error().Err(err).Msg("error inserting agent into db")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// Lists all agents in the database
func (d *daemon) getAgents(c *gin.Context) {
	ctx := context.Background()

	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is trying to list all agents")

	sub := admin.Username
	dom := admin.Organization
	obj := "agents::Admins"
	act := "read"
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing agent listing")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		agents, err := d.db.GetAgents(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Error getting agents")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		var resp []AgentResponse
		for _, a := range agents {
			aFromPool, err := d.agentPool.getAgent(a.Name)
			var aResp AgentResponse
			if err != nil {
				log.Error().Err(err).Msg("error getting agent from pool")
				aResp = AgentResponse{
					Name:      a.Name,
					Connected: false,
					Url:       a.Url,
					Tls:       a.Tls,
				}
				resp = append(resp, aResp)
				continue
			}
			aResp = AgentResponse{
				Name:       a.Name,
				Connected:  true,
				Url:        a.Url,
				Tls:        a.Tls,
				StateLock:  aFromPool.StateLock,
			}
			resp = append(resp, aResp)
		}

		c.JSON(http.StatusOK, APIResponse{Status: "OK", Agents: resp})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// TODO: Not critical atm can just delete and recreate the agent
// Updates an agent with ex. new sign, authkey or url recreates a connection with the new information
func (d *daemon) updateAgent(c *gin.Context) {

}

// Removes and closes connections to agent, and removes from database
func (d *daemon) deleteAgent(c *gin.Context) {
	ctx := context.Background()

	agentName := c.Param("agent")

	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("Agent", agentName).
		Msg("AdminUser is trying to delete an agent")

	sub := admin.Username
	dom := admin.Organization
	obj := "agents::Admins"
	act := "write"
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing agent deletion")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		exists, err := d.db.CheckIfAgentExists(ctx, agentName)
		if err != nil {
			log.Error().Err(err).Msgf("Error checking if agent exists")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		if !exists {
			log.Error().Str("agentName", agentName).Msg("agent with that name does not exists")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "agent with that name does not exists"})
			return
		}

		// TODO: make sure that go routines connected to the agent is removed
		d.agentPool.removeAgent(agentName)

		if err := d.db.DeleteAgentByName(ctx, agentName); err != nil {
			log.Error().Err(err).Msgf("Error deleting agent")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// Remove streams and recreate if it for some reason lost connection
func (d *daemon) reconnectAgent(c *gin.Context) {
	ctx := context.Background()

	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is trying to reconnect to an agent")

	sub := admin.Username
	dom := admin.Organization
	obj := "agents::Admins"
	act := "write"
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing agent reconnection")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		agentName := c.Param("agent")
		d.agentPool.removeAgent(agentName)

		exists, err := d.db.CheckIfAgentExists(ctx, agentName)
		if err != nil {
			log.Error().Err(err).Msgf("Error checking if agent exists")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		if !exists {
			log.Error().Str("agentName", agentName).Msg("agent with that name does not exists")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "agent with that name does not exists"})
			return
		}

		dbAgent, err := d.db.GetAgentByName(ctx, agentName)
		if err != nil {
			log.Error().Err(err).Msg("error getting agent from db")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("error getting agent from db: %v", err)})
			return
		}
		serviceConf := ServiceConfig{
			Grpc:       dbAgent.Url,
			AuthKey:    dbAgent.AuthKey,
			SignKey:    dbAgent.SignKey,
			TLSEnabled: dbAgent.Tls,
		}
		conn, memoryInstalled, err := NewAgentConnection(serviceConf)
		if err != nil {
			log.Error().Err(err).Msg("error reconnecting to agent")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("error reconnecting to agent: %v", err)})
			return
		}

		streamCtx, cancel := context.WithCancel(context.Background())
		agentForPool := &Agent{
			Name:      dbAgent.Name,
			Conn:      conn,
			StateLock: false,
			Errors:    []error{},
			Close:     cancel,
			Resources: AgentResources{
				MemoryInstalled: memoryInstalled,
			},
		}

		if err := d.agentPool.connectToStreams(streamCtx, d.newLabs, agentForPool, d.eventpool); err != nil {
			log.Error().Err(err).Msg("error connecting to agent streams")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("error connecting to agent streams: %v", err)})
			return
		}

		d.agentPool.addAgent(agentForPool)

		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) lockAgentState(c *gin.Context) {
	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is trying to delete an agent")

	sub := admin.Username
	dom := admin.Organization
	obj := "agents::Admins"
	act := "write"
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing agent reconnection")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		agentName := c.Param("agent")
		if err := d.agentPool.updateAgentState(agentName, true); err != nil {
			log.Error().Err(err).Msg("error updating agent state")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "agent does not exist"})
			return
		}

		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) unlockAgentState(c *gin.Context) {
	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is trying to delete an agent")

	sub := admin.Username
	dom := admin.Organization
	obj := "agents::Admins"
	act := "write"
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing agent reconnection")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		agentName := c.Param("agent")
		if err := d.agentPool.updateAgentState(agentName, false); err != nil {
			log.Error().Err(err).Msg("error updating agent state")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "agent does not exist in agent pool"})
			return
		}

		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// TODO Find a better way to authenticate users than sending jwt as get query parameter
func (d *daemon) agentWebsocket(c *gin.Context) {
	agentName := c.Param("agent")

	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer ws.Close()

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
		sub := string(claims["sub"].(string))
		dom := string(claims["organization"].(string))
		obj := "agents::Admins"
		act := "read"
		if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
			if err != nil {
				log.Error().Err(err).Msgf("Encountered an error while authorizing agent deletion")
				ws.WriteMessage(mt, []byte("internal server error"))
				return
			}
			// Send agent metrics if authorized
			for {
				agent, err := d.agentPool.getAgent(agentName)
				if err != nil {
					ws.WriteMessage(mt, []byte("agent not connected"))
					return
				}

				agentJson, err := json.Marshal(agent.Resources)
				err = ws.WriteMessage(mt, agentJson)
				time.Sleep(2 * time.Second)
			}
		}
		ws.WriteMessage(mt, []byte("unauthorized"))
		return
	}

}

// Validates the agentRequest sent by the user
// You can enable or disable specific validation checks with their corresponding booleans
func validateRequestParams(req AgentRequest, name, url, signKey, authKey bool) error {
	if req.Name == "" && name {
		return errors.New("name can't be empty")
	}
	if req.Url == "" && url {
		return errors.New("url can't be empty")
	}
	if req.SignKey == "" && signKey {
		return errors.New("sign-key can't be empty")
	}
	if req.AuthKey == "" && authKey {
		return errors.New("auth-key can't be empty")
	}
	return nil
}
