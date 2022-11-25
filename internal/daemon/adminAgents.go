package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/agent"
	"github.com/aau-network-security/haaukins-daemon/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (d *daemon) adminAgentsSubrouter(r *gin.RouterGroup) {
	agent := r.Group("/agents")
	agent.Use(d.adminAuthMiddleware())

	// CRUD
	agent.POST("", d.newAgent)
	agent.GET("", d.getAgents)
	agent.PUT("", d.updateAgent)
	agent.DELETE("", d.deleteAgent)

	// Additional routes
	agent.GET("/reconnect/:agent", d.reconnectAgent)
	agent.GET("/agentstate/lock/:agent", d.lockAgentState)
	agent.GET("/agentstate/unlock/:agent", d.lockAgentState)
}

type agentRequest struct {
	Name    string `json:"name"`
	Url     string `json:"url,omitempty"`
	SignKey string `json:"sign-key,omitempty"`
	AuthKey string `json:"auth-key,omitempty"`
	Tls     bool   `json:"tls,omitempty"`
}

// Creates a new agent connection and stores connection information in the database
func (d *daemon) newAgent(c *gin.Context) {
	ctx := context.Background()

	var req agentRequest
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
		conn, err := NewAgentConnection(serviceConf)
		if err != nil {
			log.Error().Err(err).Msg("error connecting to new agent")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("error connecting to new agent: %v", err)})
			return
		}

		streamCtx, cancel := context.WithCancel(context.Background())
		agentForPool := &agent.Agent{
			Name:      req.Name,
			Conn:      conn,
			StateLock: false,
			Errors:    []error{},
			Close:     cancel,
		}

		if err := agentForPool.ConnectToStreams(streamCtx, d.newLabs); err != nil {
			log.Error().Err(err).Msg("error connecting to agent streams")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("error connecting to agent streams: %v", err)})
			return
		}

		d.agentPool.AddAgent(agentForPool)

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

		c.JSON(http.StatusOK, APIResponse{Status: "OK", Agents: agents})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// Updates an agent with ex. new sign, authkey or url recreates a connection with the new information
func (d *daemon) updateAgent(c *gin.Context) {

}

// Removes and closes connections to agent, and removes from database
func (d *daemon) deleteAgent(c *gin.Context) {
	ctx := context.Background()

	var req agentRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error parsing request"})
		return
	}

	// Validate all request parameters
	if err := validateRequestParams(req, true, false, false, false); err != nil {
		log.Error().Err(err).Msg("error validation request")
		c.JSON(http.StatusBadRequest, APIResponse{Status: err.Error()})
		return
	}

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
			log.Error().Err(err).Msgf("Encountered an error while authorizing agent deletion")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		exists, err := d.db.CheckIfAgentExists(ctx, req.Name)
		if err != nil {
			log.Error().Err(err).Msgf("Error checking if agent exists")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		if !exists {
			log.Error().Str("agentName", req.Name).Msg("agent with that name does not exists")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "agent with that name does not exists"})
			return
		}

		// TODO: make sure that go routines connected to the agent is removed
		d.agentPool.RemoveAgent(req.Name)

		if err := d.db.DeleteAgentByName(ctx, req.Name); err != nil {
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
		d.agentPool.RemoveAgent(agentName)

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
		conn, err := NewAgentConnection(serviceConf)
		if err != nil {
			log.Error().Err(err).Msg("error reconnecting to agent")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("error reconnecting to agent: %v", err)})
			return
		}

		streamCtx, cancel := context.WithCancel(context.Background())
		agentForPool := &agent.Agent{
			Name:      dbAgent.Name,
			Conn:      conn,
			StateLock: false,
			Errors:    []error{},
			Close:     cancel,
		}

		if err := agentForPool.ConnectToStreams(streamCtx, d.newLabs); err != nil {
			log.Error().Err(err).Msg("error connecting to agent streams")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("error connecting to agent streams: %v", err)})
			return
		}

		d.agentPool.AddAgent(agentForPool)

		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) lockAgentState(c *gin.Context) {

}

func (d *daemon) unlockAgentState(c *gin.Context) {

}

// Validates the agentRequest sent by the user
// You can enable or disable specific validation checks with their corresponding booleans
func validateRequestParams(req agentRequest, name, url, signKey, authKey bool) error {
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
