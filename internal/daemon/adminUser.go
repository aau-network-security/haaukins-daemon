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

	token, err := d.createAdminToken(ctx, user)
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
	log.Debug().Msgf("admin claims: %v", admin)
	d.auditLogger.Info().
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is creating a new user")

	// Check if role to assign actually exists
	role, err := d.db.GetRoleById(ctx, req.RoleId)
	if err != nil {
		log.Error().Err(err).Msgf("Error finding role for new user")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}
	// Check if org to assign actually exists
	_, err = d.db.GetOrgById(ctx, req.OrganizationId)
	if err != nil {
		log.Error().Err(err).Msgf("Error finding org for new user")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}

	if admin.WriteAll { // User is allowed to create new users with no restrictions
		alreadyExists, err := d.createAdminUser(ctx, req)
		if err != nil || alreadyExists {
			if alreadyExists {
				log.Error().Err(err).Msgf("Error creating admin user")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "User already exists"})
				return
			}
			log.Error().Err(err).Msgf("Error creating admin user")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	} else if admin.WriteLocal { // User is only allowed to write within their organization
		// Check if admin has access to organization
		if !authOrganizationAccess(admin, req.OrganizationId) {
			c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized, you do not have access to this organization"})
			return
		}

		// Check if admin can attach desired role to user
		if !authRoleAssignment(admin, role) {
			c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized, you cannot create a user which has more permissions than yourself"})
			return
		}
		alreadyExists, err := d.createAdminUser(ctx, req)
		if err != nil || alreadyExists {
			if alreadyExists {
				log.Error().Err(err).Msgf("Error creating admin user")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "User already exists"})
				return
			}
			log.Error().Err(err).Msgf("Error creating admin user")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) deleteAdminUser(c *gin.Context) {

}

func (d *daemon) updateAdminUser(c *gin.Context) {

}

func (d *daemon) getAdminUser(c *gin.Context) {

}

func (d *daemon) createAdminUser(ctx context.Context, user adminUserRequest) (bool, error) {
	pwHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}
	newUser := database.CreateAdminUserParams{
		Username:       user.Username,
		Password:       string(pwHash),
		Email:          user.Email,
		RoleID:         user.RoleId,
		OrganizationID: user.OrganizationId,
	}
	// Create the admin user
	if err := d.db.CreateAdminUser(ctx, newUser); err != nil {
		// User already exists
		return true, err
	}
	return false, nil
}
