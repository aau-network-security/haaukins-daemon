package daemon

import (
	"context"
	"net/http"

	"github.com/aau-network-security/haaukins-daemon/internal/database"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

type adminUserRequest struct {
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	Email          string `json:"email,omitempty"`
	RoleId         int32  `json:"role_id,omitempty"`
	OrganizationId int32  `json:"organization_id,omitempty"`
}

func (d *daemon) adminUserSubrouter(r *gin.RouterGroup) {
	// Public endpoints
	r.Use(corsMiddleware())
	r.POST("/login", d.adminLogin)

	// Private endpoints
	r.Use(d.adminAuthMiddleware())
	r.POST("", d.newAdminUser)
	r.GET("", d.getAdminUser)
	r.PUT("", d.updateAdminUser)
	r.DELETE("", d.deleteAdminUser)

}

func (d *daemon) adminLogin(c *gin.Context) {
	ctx := context.Background()
	var req adminUserRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}

	// Query is case insensitive and uses the capitalized username for comparison
	//username := strings.ToUpper(req.Username)

	user, err := d.db.GetAdminUser(ctx, req.Username)
	if err != nil {
		log.Error().Err(err).Msgf("Error in admin login. Could not find user with username: %s", req.Username)
		// Run hashing algorithm to prevent timed enumeration attacks on usernames
		dummyHash := "$2a$10$s8RIrctKwSA/jib7jSaGE.Z4TdukcRP/Irkxse5dotyYT0uHb3b.2"
		fakePassword := "fakepassword"
		_ = verifyPassword(dummyHash, fakePassword)
		c.JSON(http.StatusOK, APIResponse{Status: "Incorrect username or password"})
		return
	}

	match := verifyPassword(user.Password, req.Password)
	if !match {
		c.JSON(http.StatusOK, APIResponse{Status: "Incorrect username or password"})
		return
	}

	token, err := d.createAdminToken(user)
	if err != nil {
		log.Error().Err(err).Msg("Error creating token")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, APIResponse{Status: "OK", Token: token})
}

func (d *daemon) newAdminUser(c *gin.Context) {
	ctx := context.Background()
	var req adminUserRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}
	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is creating a new user")

	adminRole, err := d.db.GetRoleById(ctx, admin.RoleID)
	if err != nil {
		log.Error().Err(err).Msgf("Error finding role claimned by user: %s", admin.Username)
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}
	// TODO Fix if not super admin
	_, err = d.db.GetRoleById(ctx, req.RoleId)
	if err != nil {
		log.Error().Err(err).Msgf("Error finding role for new user")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}

	_, err = d.db.GetOrgById(ctx, req.OrganizationId)
	if err != nil {
		log.Error().Err(err).Msgf("Error finding org for new user")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}

	if adminRole.WriteAll { // User is allowed to create new users with no restrictions
		pwHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Error().Err(err).Msgf("Error generating password hash")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		newUser := database.CreateAdminUserParams{
			Username:       req.Username,
			Password:       string(pwHash),
			Email:          req.Email,
			RoleID:         req.RoleId,
			OrganizationID: req.OrganizationId,
		}

		if err := d.db.CreateAdminUser(ctx, newUser); err != nil {
			log.Error().Err(err).Msgf("Error creating admin user")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "User already exists"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
	} else {
		// TODO Fix if not super admin
		c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
	}

}

func (d *daemon) deleteAdminUser(c *gin.Context) {

}

func (d *daemon) updateAdminUser(c *gin.Context) {

}

func (d *daemon) getAdminUser(c *gin.Context) {

}
