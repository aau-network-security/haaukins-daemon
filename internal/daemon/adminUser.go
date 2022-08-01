package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/database"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

type adminUserRequest struct {
	Username            string `json:"username,omitempty"`
	Password            string `json:"password,omitempty"`
	Email               string `json:"email,omitempty"`
	Role                string `json:"role,omitempty"`
	Organization        string `json:"organization,omitempty"`
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
	// user.GET("", d.getAdminUsers)
	// user.PUT("", d.updateAdminUser)
	// user.DELETE("", d.deleteAdminUser)

}

func (d *daemon) adminLogin(c *gin.Context) {
	ctx := context.Background()
	var req adminUserRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}

	// Get user information
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

	// Check if password matches that which is in the database
	match := verifyPassword(user.Password, req.Password)
	if !match {
		c.JSON(http.StatusOK, APIResponse{Status: "Incorrect username or password"})
		return
	}

	// If password is correct create and serve jwt token
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
	// Unpack user request into go struct
	var req adminUserRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}

	// Unpack the jwt claims passed in the gin context to a struct
	admin := unpackAdminClaims(c)
	log.Debug().Msgf("admin claims: %v", admin)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("NewUser", req.Username).
		Msg("AdminUser is trying to create a new user")

	// Check if role to assign actually exists
	//Todo casbin check on role
	// Check if org to assign actually exists
	_, err := d.db.GetOrgByName(ctx, req.Organization)
	if err != nil {
		log.Error().Err(err).Msgf("Error finding org for new user")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Organization does not exist"})
		return
	}
	sub := admin.Username
	dom := req.Organization
	obj := req.Role
	act := "write"
	if err := d.enforcer.LoadPolicy(); err != nil {
		log.Error().Err(err).Msgf("Error loading policies")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}
	ok, err := d.enforcer.Enforce(fmt.Sprint(sub), dom, obj, act)
	log.Debug().Str("subject", sub).Str("dom", dom).Str("obj", obj).Msgf("Trying to authorize: %v, %v", ok, err)
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		// Password should be more than 8 characters
		if len(req.Password) < 8 {
			c.JSON(http.StatusBadRequest, APIResponse{Status: "Password has to be at least 8 characters"})
			return
		}
		// Create new user if it does not already exist
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
		// Create casbin user
		if _, err := d.enforcer.AddRoleForUserInDomain(strings.ToLower(req.Username), req.Role, req.Organization); err != nil {
			log.Error().Err(err).Msgf("Encountered an error while assigning user to role and org")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// func (d *daemon) deleteAdminUser(c *gin.Context) {
// 	ctx := context.Background()
// 	// Unpack user request into go struct
// 	var req adminUserRequest
// 	if err := c.BindJSON(&req); err != nil {
// 		log.Error().Err(err).Msg("Error parsing request data: ")
// 		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
// 		return
// 	}
// 	// Unpack the jwt claims passed in the gin context to a struct
// 	admin := unpackAdminClaims(c)
// 	log.Debug().Msgf("admin claims: %v", admin)
// 	d.auditLogger.Info().
// 		Time("UTC", time.Now().UTC()).
// 		Str("AdminUser", admin.Username).
// 		Str("AdminEmail", admin.Email).
// 		Str("Username", req.Username).
// 		Msg("AdminUser is trying to delete user")

// 	// Getting info for user to delete
// 	user, err := d.db.GetAdminUser(ctx, req.Username)
// 	if err != nil {
// 		log.Error().Err(err).Msg("Error getting admin user for deletion")
// 		c.JSON(http.StatusBadRequest, APIResponse{Status: "Could not find user to delete"})
// 		return
// 	}
// 	// Getting role info for user to delete
// 	userRole, err := d.db.GetRoleById(ctx, user.RoleID)
// 	if err != nil {
// 		log.Error().Err(err).Msg("Error getting user role for user to delete")
// 		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error, please contact an server administrator"})
// 		return
// 	}

// 	if admin.WriteAll { // User is allowed to create new users with no restrictions
// 		if err := d.db.DeleteAdminUser(ctx, req.Username); err != nil {
// 			log.Error().Err(err).Msg("Error deleting admin user")
// 			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
// 			return
// 		}
// 		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
// 		return
// 	} else if admin.WriteLocal { // User is only allowed to write within their organization
// 		if !authOrganizationAccess(admin, user.OrganizationID) {
// 			c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized, you do not have access to this organization"})
// 			return
// 		}
// 		// Check if admin can actually delete the user, deny if user to delete has more privileges
// 		if !authRoleAccess(admin, userRole) {
// 			c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized, you cannot delete a user which has more permissions than yourself"})
// 			return
// 		}
// 		// If authorized delete the user
// 		if err := d.db.DeleteAdminUser(ctx, req.Username); err != nil {
// 			log.Error().Err(err).Msg("Error deleting admin user")
// 			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
// 			return
// 		}
// 		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
// 		return
// 	}

// 	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
// }

// func (d *daemon) updateAdminUser(c *gin.Context) {
// 	ctx := context.Background()
// 	// Unpack user request into go struct
// 	var req adminUserRequest
// 	if err := c.BindJSON(&req); err != nil {
// 		log.Error().Err(err).Msg("Error parsing request data: ")
// 		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
// 		return
// 	}
// 	// Unpack the jwt claims passed in the gin context to a struct
// 	admin := unpackAdminClaims(c)
// 	log.Debug().Msgf("admin claims: %v", admin)
// 	d.auditLogger.Info().
// 		Time("UTC", time.Now().UTC()).
// 		Str("AdminUser", admin.Username).
// 		Str("AdminEmail", admin.Email).
// 		Str("Username", req.Username).
// 		Msg("AdminUser is updating user")

// 	// Get current user info for comparison
// 	currUser, err := d.db.GetAdminUser(ctx, req.Username)
// 	if err != nil {
// 		log.Error().Err(err).Msg("Error getting user")
// 		c.JSON(http.StatusBadRequest, APIResponse{Status: "Could not find user to update"})
// 		return
// 	}
// 	// Get current user role to make sure under privileged user does not change pw for fx a super admin
// 	currUserRole, err := d.db.GetRoleById(ctx, currUser.RoleID)
// 	if err != nil {
// 		log.Error().Err(err).Msg("Error getting user role for user to delete")
// 		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error, please contact an server administrator"})
// 		return
// 	}

// 	if admin.WriteAll { // No restrictions
// 		// Update the current user
// 		if err := d.updateAdminUserQuery(ctx, req, currUser, admin); err != nil {
// 			log.Error().Err(err).Msg("Error updating user")
// 			c.JSON(http.StatusBadRequest, APIResponse{Status: fmt.Sprintf("Could not update user: %s", err)})
// 			return
// 		}
// 		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
// 		return
// 	} else if admin.WriteLocal { // Restricted to organization, can only manipulate users with same role privileges or less
// 		// Check if admin has access to organization
// 		if !authOrganizationAccess(admin, currUser.OrganizationID) {
// 			c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized, you do not have access to this organization"})
// 			return
// 		}
// 		// Check if admin can update the desired user
// 		if !authRoleAccess(admin, currUserRole) {
// 			c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized, you cannot update a user which has more permissions than yourself"})
// 			return
// 		}
// 		// Update the current user
// 		if err := d.updateAdminUserQuery(ctx, req, currUser, admin); err != nil {
// 			log.Error().Err(err).Msg("Error updating user")
// 			c.JSON(http.StatusBadRequest, APIResponse{Status: fmt.Sprintf("Could not update user: %s", err)})
// 			return
// 		}
// 		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
// 		return
// 	} else if admin.Username == currUser.Username { // if the user wants to update itself
// 		// Update the current user
// 		if err := d.updateAdminUserQuery(ctx, req, currUser, admin); err != nil {
// 			log.Error().Err(err).Msg("Error updating user")
// 			c.JSON(http.StatusBadRequest, APIResponse{Status: fmt.Sprintf("Could not update user: %s", err)})
// 			return
// 		}
// 		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
// 		return
// 	}

// 	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
// }

func (d *daemon) getAdminUser(c *gin.Context) {
	ctx := context.Background()
	// get username parameter from url
	username := c.Param("username")

	// Unpack the jwt claims passed in the gin context to a struct
	admin := unpackAdminClaims(c)
	log.Debug().Msgf("admin claims: %v", admin)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("Username", username).
		Msg("AdminUser is listing users")

	// Get the user to return without showing the pw hash
	user, err := d.db.GetAdminUserNoPw(ctx, username)
	if err != nil {
		log.Error().Err(err).Msg("Error getting admin user")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Could not find user"})
		return
	}

	sub := admin.Username
	dom := user.Organization
	obj := '*'
	act := "write"
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}

	// if admin.ReadAll { // if user can read all, return with no restrictions
	// 	c.JSON(http.StatusOK, APIResponse{Status: "OK", User: &user})
	// 	return
	// } else if admin.ReadLocal { // Only show user if within the requesting users organization
	// 	if !authOrganizationAccess(admin, user.OrganizationID) {
	// 		c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized, you do not have access to this organization"})
	// 		return
	// 	}
	// 	c.JSON(http.StatusOK, APIResponse{Status: "OK", User: &user})
	// 	return
	// }

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// func (d *daemon) getAdminUsers(c *gin.Context) {
// 	ctx := context.Background()

// 	// Unpack the jwt claims passed in the gin context to a struct
// 	admin := unpackAdminClaims(c)
// 	log.Debug().Msgf("admin claims: %v", admin)
// 	d.auditLogger.Info().
// 		Time("UTC", time.Now().UTC()).
// 		Str("AdminUser", admin.Username).
// 		Str("AdminEmail", admin.Email).
// 		Msg("AdminUser is listing users")

// 	if admin.ReadAll { // return all users in database without pwhash
// 		// When org id is zero it gets all users from the db
// 		users, err := d.db.GetAdminUsers(ctx, 0)
// 		if err != nil {
// 			log.Error().Err(err).Msg("Error getting admin users")
// 			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
// 			return
// 		}
// 		c.JSON(http.StatusOK, APIResponse{Status: "OK", Users: users})
// 		return
// 	} else if admin.ReadLocal { // Return only users within the requesting users organization
// 		// By specifying an org id which is not 0, the query only returns users withing that organization
// 		users, err := d.db.GetAdminUsers(ctx, admin.OrganizationID)
// 		if err != nil {
// 			log.Error().Err(err).Msg("Error getting admin users")
// 			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
// 			return
// 		}
// 		c.JSON(http.StatusOK, APIResponse{Status: "OK", Users: users})
// 		return
// 	}

// 	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
// }

func (d *daemon) createAdminUser(ctx context.Context, user adminUserRequest) (bool, error) {
	// Create password hash from password
	pwHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}
	// Passing request data to query param struct
	newUser := database.CreateAdminUserParams{
		Username:     user.Username,
		Password:     string(pwHash),
		Email:        user.Email,
		Role:         user.Role,
		Organization: user.Organization,
	}
	// Create the admin user
	if err := d.db.CreateAdminUser(ctx, newUser); err != nil {
		// User already exists
		return true, err
	}
	return false, nil
}

func (d *daemon) updateAdminUserQuery(ctx context.Context, updatedUser adminUserRequest, currUser database.AdminUser, admin AdminClaims) error {
	// Get admininfo for password verification to prevent unauthorized updates of users
	adminInfo, err := d.db.GetAdminUser(ctx, admin.Username)
	if err != nil {
		return err
	}
	match := verifyPassword(adminInfo.Password, updatedUser.VerifyAdminPassword)
	if !match {
		return errors.New("Admin verification failed, password did not match")
	}

	// Update password if changed
	if !verifyPassword(currUser.Password, updatedUser.Password) && updatedUser.Password != "" {
		log.Debug().Msg("Updating password")
		// Password should be longer than 8 characters
		if len(updatedUser.Password) < 8 {
			return errors.New("Password must be at least 8 characters")
		}
		// Generate new password hash from the updated password
		newPwHash, err := bcrypt.GenerateFromPassword([]byte(updatedUser.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		// Pass the password hash and user to update into the query param struct
		newPw := database.UpdateAdminPasswordParams{
			Password: string(newPwHash),
			Username: updatedUser.Username,
		}
		// Update the password
		if err := d.db.UpdateAdminPassword(ctx, newPw); err != nil {
			return fmt.Errorf("Error updating password: %s", err)
		}
	}

	// Update email if changed
	if updatedUser.Email != currUser.Email {
		log.Debug().Msg("Updating email")
		// Pass the email and user to update into the query param struct
		newEmail := database.UpdateAdminEmailParams{
			Email:    updatedUser.Email,
			Username: updatedUser.Username,
		}
		// Update the email
		if err := d.db.UpdateAdminEmail(ctx, newEmail); err != nil {
			return fmt.Errorf("Error updating email: %s", err)
		}
	}

	return nil
}
