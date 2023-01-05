package daemon

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

func (d *daemon) eventTeamSubrouter(r *gin.RouterGroup) {
	team := r.Group("/teams")

	team.POST("/login", d.teamLogin)
	team.POST("/signup", d.teamSignup)

}

type TeamRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Email     string `json:"email"`
	EventTag  string `json:"eventTag"`
	SecretKey string `json:"secretKey"`
}

type TeamResponse struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

func (d *daemon) teamLogin(c *gin.Context) {
	ctx := context.Background()
	var req TeamRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}

	event, err := d.db.GetEventByTag(ctx, req.EventTag)
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
		Eventid:  event.ID,
	}
	team, err := d.db.GetTeamFromEventByUsername(ctx, arg)
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

	match := verifyPassword(team.Password, req.Password)
	if !match {
		c.JSON(http.StatusUnauthorized, APIResponse{Status: incorrectUsernameOrPasswordError})
		return
	}

	token, err := d.createParticipantToken(ctx, team, req.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("Error creating token")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}

	teamInfo := &TeamResponse{
		Username: team.Username,
		Email:    team.Email,
	}
	c.JSON(http.StatusOK, APIResponse{Status: "OK", Token: token, TeamInfo: teamInfo})
}

// TODO Add measures to verify email address
func (d *daemon) teamSignup(c *gin.Context) {
	ctx := context.Background()

	var req TeamRequest
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
			Valid: false,
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
		Username: req.Username,
		Email:    req.Email,
		Lab:      nil,
	}
	if err := event.AddTeam(team); err != nil {
		log.Error().Err(err).Msg("error adding team to eventpool")
	}

	if EventType(dbEvent.Type) == TypeBeginner {
		// Put team into waitingForLabs Queue if beginner type event
		go func() {
			defer func() {
				if recover() != nil {
					log.Debug().Msg("channel closed while sending team to queue")
				}
			}()
			log.Info().Str("username", team.Username).Msg("putting team into queue for beginner lab")
			event.TeamsWaitingForBrowserLabs <- team
			log.Info().Str("username", team.Username).Msg("team got taken out of queue, exiting go routine")
		}()
	}

	// For debugging purposes
	for _, lab := range d.eventpool.Events[event.Config.Tag].Labs {
		log.Debug().Str("labTag", lab.LabInfo.Tag).Str("labParentAgent", lab.ParentAgent).Msg("lab in event")
	}
	c.JSON(http.StatusOK, APIResponse{Status: "OK", Token: token})
}

// TODO When email functionality has been implemented, make reset password function
