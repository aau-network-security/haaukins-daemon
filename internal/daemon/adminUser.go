package daemon

import (
	"context"
	"fmt"
	"net/http"
	"time"

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
	VerifyAdminPassword string `json:"verify_admin_password,omitempty"`
}

func (d *daemon) adminUserSubrouter(r *gin.RouterGroup) {
	user := r.Group("/users")
	// Public endpoints
	user.Use(corsMiddleware())
	user.POST("/login", d.adminLogin)

	// Private endpoints
	user.Use(d.adminAuthMiddleware())
	user.POST("", d.newAdminUser)
	user.GET("/:username", d.getAdminUser)
	user.GET("", d.getAdminUsers)
	user.PUT("", d.updateAdminUser)
	user.DELETE("", d.deleteAdminUser)

}

func (d *daemon) adminLogin(c *gin.Context) {
	ctx := context.Background()
	var req adminUserRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}

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
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("NewUser", req.Username).
		Msg("AdminUser is trying to create a new user")

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
		if !authRoleAccess(admin, role) {
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
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("Username", req.Username).
		Msg("AdminUser is trying to delete user")

	// Getting info for user to delete
	user, err := d.db.GetAdminUser(ctx, req.Username)
	if err != nil {
		log.Error().Err(err).Msg("Error getting admin user for deletion")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Could not find user to delete"})
		return
	}
	userRole, err := d.db.GetRoleById(ctx, user.RoleID)
	if err != nil {
		log.Error().Err(err).Msg("Error getting user role for user to delete")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error, please contact an server administrator"})
		return
	}

	if admin.WriteAll { // User is allowed to create new users with no restrictions
		if err := d.db.DeleteAdminUser(ctx, req.Username); err != nil {
			log.Error().Err(err).Msg("Error deleting admin user")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	} else if admin.WriteLocal { // User is only allowed to write within their organization
		if !authOrganizationAccess(admin, user.OrganizationID) {
			c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized, you do not have access to this organization"})
			return
		}
		// Check if admin can attach desired role to user
		if !authRoleAccess(admin, userRole) {
			c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized, you cannot delete a user which has more permissions than yourself"})
			return
		}
		if err := d.db.DeleteAdminUser(ctx, req.Username); err != nil {
			log.Error().Err(err).Msg("Error deleting admin user")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) updateAdminUser(c *gin.Context) {
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
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("Username", req.Username).
		Msg("AdminUser is updating user")

	user, err := d.db.GetAdminUser(ctx, req.Username)
	if err != nil {
		log.Error().Err(err).Msg("Error getting user")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Could not find user to update"})
		return
	}

	if admin.WriteAll {
		err := 
	} else if admin.WriteLocal {

	} else if admin.Username == user.Username {

	}

}

func (d *daemon) getAdminUser(c *gin.Context) {
	ctx := context.Background()
	username := c.Param("username")

	admin := unpackAdminClaims(c)
	log.Debug().Msgf("admin claims: %v", admin)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("Username", username).
		Msg("AdminUser is listing users")

	user, err := d.db.GetAdminUserNoPw(ctx, username)
	if err != nil {
		log.Error().Err(err).Msg("Error getting admin user")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Could not find user"})
		return
	}

	if admin.ReadAll {
		c.JSON(http.StatusOK, APIResponse{Status: "OK", User: &user})
		return
	} else if admin.ReadLocal {
		if !authOrganizationAccess(admin, user.OrganizationID) {
			c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized, you do not have access to this organization"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK", User: &user})
		return
	}

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) getAdminUsers(c *gin.Context) {
	ctx := context.Background()

	admin := unpackAdminClaims(c)
	log.Debug().Msgf("admin claims: %v", admin)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is listing users")

	if admin.ReadAll {
		// When org id is zero it gets all users from the db
		users, err := d.db.GetAdminUsers(ctx, 0)
		if err != nil {
			log.Error().Err(err).Msg("Error getting admin users")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK", Users: users})
		return
	} else if admin.ReadLocal {
		users, err := d.db.GetAdminUsers(ctx, admin.OrganizationID)
		if err != nil {
			log.Error().Err(err).Msg("Error getting admin users")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK", Users: users})
		return
	}

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
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

func (d *daemon) updateAdminUserQuery(ctx context.Context, updatedUser adminUserRequest, currUser database.AdminUser, admin AdminClaims) error {
	adminInfo, err := d.db.GetAdminUser(ctx, admin.Username)
	if err != nil {
		return err
	}
	match := verifyPassword(adminInfo.Password, updatedUser.VerifyAdminPassword)
	if !match {
		return fmt.Error("Admin verification failed, password did not match")
	}
	if updatedUser.Password != currUser.Password {
		if up
	}
}
