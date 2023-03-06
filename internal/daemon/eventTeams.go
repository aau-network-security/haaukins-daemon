package daemon

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
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
		return "waitingForLab"
	case InQueue:
		return "inLabQueue"
	case RunningExerciseCommand:
		return "RunningExCommand"
	case Idle:
		return "idle"
	default:
		return "unknown"
	}
}

func (d *daemon) eventTeamSubrouter(r *gin.RouterGroup) {
	team := r.Group("/teams")

	team.POST("/login", d.teamLogin)
	team.POST("/signup", d.teamSignup)

	team.Use(d.eventAuthMiddleware())
	team.GET("/self", d.getOwnTeam)
}

type TeamSignupRequest struct {
	Username        string `json:"username" binding:"required"`
	Password        string `json:"password" binding:"required"`
	ConfirmPassword string `json:"confirmPassword" binding:"required"`
	Email           string `json:"email" binding:"required"`
	EventTag        string `json:"eventTag"`
	SecretKey       string `json:"secretKey"`
}

type TeamLoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	EventTag string `json:"eventTag"`
}

type TeamResponse struct {
	Username string       `json:"username,omitempty"`
	Email    string       `json:"email,omitempty"`
	Status   string       `json:"status,omitempty"`
	Lab      *LabResponse `json:"lab,omitempty"`
}

func (d *daemon) teamLogin(c *gin.Context) {
	ctx := context.Background()
	var req TeamLoginRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}

	dbEvent, err := d.db.GetEventByTag(ctx, req.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("Error getting event by tag")
		if err == sql.ErrNoRows {
			c.JSON(http.StatusBadRequest, APIResponse{Status: "event does not exist"})
			return
		}
		c.JSON(http.StatusBadRequest, APIResponse{Status: "internal server error"})
		return
	}

	arg := db.GetTeamFromEventByUsernameParams{
		Username: req.Username,
		Eventid:  dbEvent.ID,
	}
	dbTeam, err := d.db.GetTeamFromEventByUsername(ctx, arg)
	if err != nil {
		if err == sql.ErrNoRows {
			dummyHash := "$2a$10$s8RIrctKwSA/jib7jSaGE.Z4TdukcRP/Irkxse5dotyYT0uHb3b.2"
			fakePassword := "fakepassword"
			_ = verifyPassword(dummyHash, fakePassword)
			c.JSON(http.StatusUnauthorized, APIResponse{Status: incorrectUsernameOrPasswordError})
			return
		}
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}

	match := verifyPassword(dbTeam.Password, req.Password)
	if !match {
		c.JSON(http.StatusUnauthorized, APIResponse{Status: incorrectUsernameOrPasswordError})
		return
	}

	token, err := d.createParticipantToken(ctx, dbTeam, req.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("Error creating token")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}

	event, _ := d.eventpool.GetEvent(req.EventTag)

	team, err := event.GetTeam(dbTeam.Username)
	if err != nil {
		log.Error().Err(err).Msg("could not find team for event")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "could not find team for event"})
		return
	}

	teamResponse := &TeamResponse{
		Username: team.Username,
		Email:    team.Email,
		Status:   team.Status.String(),
	}
	if team.Lab != nil {
		teamResponse.Lab = assembleLabResponse(team.Lab)
	}
	c.JSON(http.StatusOK, APIResponse{Status: "OK", Token: token, TeamInfo: teamResponse})
}

// TODO Add measures to verify email address
func (d *daemon) teamSignup(c *gin.Context) {
	ctx := context.Background()

	var req TeamSignupRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}

	dbEvent, err := d.db.GetEventByTag(ctx, req.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("error getting event by from database")
		if err == sql.ErrNoRows {
			c.JSON(http.StatusBadRequest, APIResponse{Status: "event does not exist"})
			return
		}
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}

	// Check if event is in event pool
	// If event is in db but not in pool something is wrong
	event, err := d.eventpool.GetEvent(req.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("error getting event from eventpool")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}

	if dbEvent.Secretkey != "" && req.SecretKey != dbEvent.Secretkey {
		c.JSON(http.StatusUnauthorized, APIResponse{Status: "invalid secretkey"})
		return
	}

	if req.Password != req.ConfirmPassword {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "passwords do not match"})
		return
	}

	pwHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("error generating password hash")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}

	newTeam := db.AddTeamParams{
		Username:  req.Username,
		Password:  string(pwHash),
		Email:     req.Email,
		Tag:       uuid.New().String()[0:8],
		EventID:   dbEvent.ID,
		CreatedAt: time.Now(),
		LastAccess: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
	}

	// Check if team for that event already exists
	arg := db.CheckIfTeamExistsForEventParams{
		Username: req.Username,
		Eventid:  dbEvent.ID,
	}
	teamExists, err := d.db.CheckIfTeamExistsForEvent(ctx, arg)
	if err != nil {
		log.Error().Err(err).Msg("error checking if team exists for event")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}
	if teamExists {
		log.Error().Msg("team already exists")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "team already exists"})
		return
	}

	// add team to database
	if err := d.db.AddTeam(ctx, newTeam); err != nil {
		log.Error().Err(err).Msg("error adding team")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}

	dbTeam := db.Team{
		Username: newTeam.Username,
		Email:    newTeam.Email,
	}
	token, err := d.createParticipantToken(ctx, dbTeam, req.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("Error creating token")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}

	team := &Team{
		Username:                   req.Username,
		Email:                      req.Email,
		Status:                     Idle,
		Lab:                        nil,
		ActiveWebsocketConnections: make(map[string]*websocket.Conn),
	}
	event.AddTeam(team)

	saveState(d.eventpool, d.conf.StatePath)

	if EventType(dbEvent.Type) == TypeBeginner && !event.IsMaxLabsReached() {
		team.Status = InQueue
		log.Info().Str("username", team.Username).Msg("putting team into queue for beginner lab")
		queueElement := event.TeamsWaitingForBrowserLabs.PushBack(team)
		team.QueueElement = queueElement
	}

	teamResponse := &TeamResponse{
		Username: team.Username,
		Email:    team.Email,
		Status:   team.Status.String(),
	}
	if team.Lab != nil {
		teamResponse.Lab = assembleLabResponse(team.Lab)
	}
	c.JSON(http.StatusOK, APIResponse{Status: "OK", Token: token, TeamInfo: teamResponse})
}

func (d *daemon) getOwnTeam(c *gin.Context) {
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
	teamResponse := &TeamResponse{
		Username: team.Username,
		Email:    team.Email,
		Status:   team.Status.String(),
	}
	if team.Lab != nil {
		teamResponse.Lab = assembleLabResponse(team.Lab)
	}

	c.JSON(http.StatusOK, APIResponse{Status: "OK", TeamInfo: teamResponse})
}

// TODO When email functionality has been implemented, make reset password function
