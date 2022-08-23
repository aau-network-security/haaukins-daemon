package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/database"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

type adminUserRequest struct {
	Username            string `json:"username,omitempty"`
	Password            string `json:"password,omitempty"`
	FullName            string `json:"full_name,omitempty"`
	Email               string `json:"email,omitempty"`
	Role                string `json:"role,omitempty"`
	Organization        string `json:"organization,omitempty"`
	VerifyAdminPassword string `json:"verify_admin_password,omitempty"`
}

func (d *daemon) adminUserSubrouter(r *gin.RouterGroup) {
	user := r.Group("/users")
	// Public endpoints
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
	// Get user information
	user, err := d.db.GetAdminUser(ctx, req.Username)
	if err != nil {
		log.Error().Err(err).Msgf("Error in admin login. Could not find user with username: %s", req.Username)
		// Run hashing algorithm to prevent timed enumeration attacks on usernames
		dummyHash := "$2a$10$s8RIrctKwSA/jib7jSaGE.Z4TdukcRP/Irkxse5dotyYT0uHb3b.2"
		fakePassword := "fakepassword"
		_ = verifyPassword(dummyHash, fakePassword)
		c.JSON(http.StatusUnauthorized, APIResponse{Status: incorrectUsernameOrPasswordError})
		return
	}

	// Check if password matches that which is in the database
	match := verifyPassword(user.Password, req.Password)
	if !match {
		c.JSON(http.StatusUnauthorized, APIResponse{Status: incorrectUsernameOrPasswordError})
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
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("NewUser", req.Username).
		Msg("AdminUser is trying to create a new user")
	// Setting up casbin request
	sub := admin.Username
	dom := admin.Organization
	obj := fmt.Sprintf("role::%s", req.Role)
	act := "write"
	log.Debug().Str("sub", sub).Str("dom", dom).Str("obj", obj).Msg("Admin")
	// TODO Waiting on an answer from github, but would be nice only to load relevant policies
	// TODO especially if we start getting alot of them
	// if err := d.enforcer.LoadPolicy(); err != nil {
	// 	log.Error().Err(err).Msgf("Error loading policies")
	// 	c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
	// 	return
	// }
	// Check if user has access
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing user creation")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		// Password should be more than 8 characters
		if len(req.Password) < 8 {
			c.JSON(http.StatusBadRequest, APIResponse{Status: passwordTooShortError})
			return
		}
		// Create new user if it does not already exist
		alreadyExists, err := d.createAdminUser(ctx, req, dom)
		if err != nil {
			log.Error().Err(err).Msgf("Error creating admin user")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		if alreadyExists {
			log.Error().Msgf("Error creating admin user: %s", userExistsError)
			c.JSON(http.StatusInternalServerError, APIResponse{Status: userExistsError})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) deleteAdminUser(c *gin.Context) {
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
		Str("Username", req.Username).
		Msg("AdminUser is trying to delete user")

	// Getting info for user to delete
	userToDelete, err := d.db.GetAdminUser(ctx, req.Username)
	if err != nil {
		log.Error().Err(err).Msg("Error getting admin user for deletion")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Could not find user to delete"})
		return
	}
	// Setting up an array of casbin requests in format sub, dom, obj and act
	var requests = [][]interface{}{
		{admin.Username, admin.Organization, fmt.Sprintf("users::%s", userToDelete.Organization), "write"},
		{admin.Username, admin.Organization, userToDelete.Role, "write"},
	}
	// Trying to authorize user
	if authorized, err := d.enforcer.BatchEnforce(requests); (authorized[0] && authorized[1]) || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing user delete")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		// Delete user info from database
		if err := d.db.DeleteAdminUser(ctx, req.Username); err != nil {
			log.Error().Err(err).Msg("Error deleting admin user")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		//Delete policy for user in db
		if _, err := d.enforcer.DeleteUser(userToDelete.Username); err != nil {
			log.Error().Err(err).Msg("Error deleting admin user policy")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error, something when wrong removing the user, please contact an admin"})
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	// User not authorized
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) updateAdminUser(c *gin.Context) {
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
		Str("Username", req.Username).
		Msg("AdminUser is updating user")

	// Get current user info for comparison
	currUser, err := d.db.GetAdminUser(ctx, req.Username)
	if err != nil {
		log.Error().Err(err).Msg("Error getting user")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Could not find user to update"})
		return
	}
	// Setting up an array of casbin requests in format sub, dom, obj and act
	var requests = [][]interface{}{
		{admin.Username, admin.Organization, fmt.Sprintf("users::%s", currUser.Organization), "write"},
		{admin.Username, admin.Organization, currUser.Role, "write"},
	}

	if authorized, err := d.enforcer.BatchEnforce(requests); (authorized[0] && authorized[1]) || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing user update")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		if err := d.updateAdminUserQuery(ctx, req, currUser, admin); err != nil {
			log.Error().Err(err).Msg("Error updating user")
			c.JSON(http.StatusBadRequest, APIResponse{Status: fmt.Sprintf("Could not update user: %s", err)})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	} else if admin.Username == currUser.Username { // if the user wants to update itself
		// Update the current user
		if err := d.updateAdminUserQuery(ctx, req, currUser, admin); err != nil {
			log.Error().Err(err).Msg("Error updating user")
			c.JSON(http.StatusBadRequest, APIResponse{Status: fmt.Sprintf("Could not update user: %s", err)})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

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
	// Setting up casbin request
	sub := admin.Username
	dom := admin.Organization
	obj := fmt.Sprintf("users::%s", user.Organization)
	act := "read"
	// Trying to authorize user
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing user read")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK", User: &user})
		return
	} else if admin.Username == user.Username {
		c.JSON(http.StatusOK, APIResponse{Status: "OK", User: &user})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) getAdminUsers(c *gin.Context) {
	ctx := context.Background()

	// Unpack the jwt claims passed in the gin context to a struct
	admin := unpackAdminClaims(c)
	log.Debug().Msgf("admin claims: %v", admin)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is listing users")

	// Setting up an array of casbin requests in format sub, dom, obj and act
	var requests = [][]interface{}{
		{admin.Username, admin.Organization, "users::Admins", "read"},
		{admin.Username, admin.Organization, fmt.Sprintf("users::%s", admin.Organization), "read"},
	}
	// Trying to authorize user
	if authorized, err := d.enforcer.BatchEnforce(requests); authorized[0] || authorized[1] || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing users read")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		// Superuser
		if authorized[0] {
			users, err := d.db.GetAdminUsers(ctx, "")
			if err != nil {
				log.Error().Err(err).Msg("Error getting admin users")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
				return
			}
			c.JSON(http.StatusOK, APIResponse{Status: "OK", Users: users})
			return
		} else if authorized[1] {
			users, err := d.db.GetAdminUsers(ctx, admin.Organization)
			if err != nil {
				log.Error().Err(err).Msg("Error getting admin users")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
				return
			}
			c.JSON(http.StatusOK, APIResponse{Status: "OK", Users: users})
			return
		}
	}

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// createAdminUser creates a new admin user and is called in the newAdminUser handler
func (d *daemon) createAdminUser(ctx context.Context, user adminUserRequest, org string) (bool, error) {
	// Create password hash from password
	pwHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}
	// Passing request data to query param struct
	newUser := database.CreateAdminUserParams{
		Username:     user.Username,
		Password:     string(pwHash),
		FullName:     user.FullName,
		Email:        user.Email,
		Role:         fmt.Sprintf("role::%s", user.Role),
		Organization: org,
	}
	log.Debug().Msgf("New User:%v", newUser)
	userExists, err := d.db.CheckIfUserExists(ctx, user.Username)
	if err != nil {
		return false, err
	}
	if userExists {
		return true, nil
	}

	// Create the admin user
	if err := d.db.CreateAdminUser(ctx, newUser); err != nil {
		return false, err
	}

	// Create casbin group
	if _, err := d.enforcer.AddGroupingPolicy(newUser.Username, newUser.Role, newUser.Organization); err != nil {
		return false, err
	}
	return false, nil
}

// updateAdminUser holds the logic for updating the pasword or email for a user, and is called from the updateAdminUser handler
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
	if updatedUser.Email != currUser.Email && updatedUser.Email != "" {
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
