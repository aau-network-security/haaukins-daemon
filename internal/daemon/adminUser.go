package daemon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

type adminUserRequest struct {
	Username            string `json:"username,omitempty"`
	Password            string `json:"password,omitempty"`
	FullName            string `json:"fullName,omitempty"`
	Email               string `json:"email,omitempty"`
	Role                string `json:"role,omitempty"`
	Organization        string `json:"organization,omitempty"`
	VerifyAdminPassword string `json:"verifyAdminPassword,omitempty"`
	LabQuota            *int32 `json:"labQuota,omitempty"`
}

type AdminUserReponse struct {
	User  AdminUserNoPw     `json:"user,omitempty"`
	Perms map[string]string `json:"perms,omitempty"`
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
	user.DELETE("/:username", d.deleteAdminUser)
	user.PATCH("/:username/role", d.updateRole)
	user.PATCH("/:username/organization", d.updateUserOrganization)
	// TODO add reset password endpoint which sends an email with a random password to the requested user.

}

// TODO Overall make sure that incoming request parameters are validated

func (d *daemon) adminLogin(c *gin.Context) {
	ctx := context.Background()
	var req adminUserRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}
	// Get user information
	user, err := d.db.GetAdminUserByUsername(ctx, req.Username)
	if err != nil {
		log.Error().Err(err).Msgf("Error in admin login. Could not find user with username: %s", req.Username)
		// Run hashing algorithm to prevent timed enumeration attacks on usernames
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

	userNoPw, err := d.db.GetAdminUserNoPwByUsername(ctx, req.Username)
	if err != nil {
		log.Error().Err(err).Msg("error getting admin user from database")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}

	perms, err := d.getDetailedUserPerms(userNoPw.Username, userNoPw.Organization)
	if err != nil {
		log.Error().Err(err).Msg("error getting implicit permissions for user")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}
	var labQuota *int32
	if !userNoPw.LabQuota.Valid {
		labQuota = nil
	} else {
		labQuota = &userNoPw.LabQuota.Int32
	}
	userToReturn := &AdminUserReponse{
		User: AdminUserNoPw{
			Username:     userNoPw.Username,
			FullName:     userNoPw.FullName,
			Email:        userNoPw.Email,
			Role:         userNoPw.Role,
			Organization: userNoPw.Organization,
			LabQuota:     labQuota,
		},
		Perms: perms,
	}

	c.JSON(http.StatusOK, APIResponse{Status: "OK", Token: token, UserInfo: userToReturn})
}

// TODO Add email func to send randomly generated password if password is set to blank for new user
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
	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("NewUser", req.Username).
		Msg("AdminUser is trying to create a new user")
	// Setting up casbin request
	// TODO Waiting on an answer from github, but would be nice only to load relevant policies
	// TODO especially if we start getting alot of them
	// if err := d.enforcer.LoadPolicy(); err != nil {
	// 	log.Error().Err(err).Msgf("Error loading policies")
	// 	c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
	// 	return
	// }
	// Check if user has access
	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, "users::Admins", "write"},
		{admin.Username, admin.Organization, fmt.Sprintf("role::%s", req.Role), "write"},
		{admin.Username, admin.Organization, fmt.Sprintf("users::%s", admin.Organization), "write"},
	}
	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); (authorized[1] && authorized[2]) || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing user creation")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		// Password should be more than 8 characters
		// TODO add case for if password length is 0, then send email with random password
		if len(req.Password) < 8 {
			c.JSON(http.StatusBadRequest, APIResponse{Status: passwordTooShortError})
			return
		}
		// Validate username
		if req.Username == "" || strings.Trim(req.Username, " ") == "" {
			c.JSON(http.StatusBadRequest, APIResponse{Status: "Invalid username"})
			return
		}
		// Create new user if it does not already exist
		org := admin.Organization
		if authorized[0] { // Superadmin
			org = req.Organization
			if req.Role == "superadmin" && org != "Admins" {
				c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized... Superadmins can only be added to the Admins organization"})
				return

			}
		}
		alreadyExists, err := d.createAdminUser(ctx, req, org)
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

	username := c.Param("username")
	// Unpack the jwt claims passed in the gin context to a struct
	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
	log.Debug().Msgf("admin claims: %v", admin)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("Username", username).
		Msg("AdminUser is trying to delete user")

	// Getting info for user to delete
	userToDelete, err := d.db.GetAdminUserByUsername(ctx, username)
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
		owner, err := d.db.CheckIfUserOwnsOrg(ctx, userToDelete.Username)
		if err != nil {
			log.Error().Err(err).Msg("Error deleting admin user")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		if owner {
			log.Warn().Msg("admin tried to delete owner of an organization")
			c.JSON(http.StatusBadRequest, APIResponse{Status: "Cannot delete an owner of an organization"})
			return
		}
		// Delete user info from database
		if err := d.db.DeleteAdminUserByUsername(ctx, userToDelete.Username); err != nil {
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
	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
	log.Debug().Msgf("admin claims: %v", admin)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("Username", req.Username).
		Msg("AdminUser is trying to update a user")

	// Get current user info for comparison
	currUser, err := d.db.GetAdminUserByUsername(ctx, req.Username)
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

	isUserSelf := admin.Username == currUser.Username
	if authorized, err := d.enforcer.BatchEnforce(requests); (authorized[0] && authorized[1]) || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing user update")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		if err := d.updateAdminUserQuery(ctx, req, currUser, admin, isUserSelf); err != nil {
			log.Error().Err(err).Msg("Error updating user")
			c.JSON(http.StatusBadRequest, APIResponse{Status: fmt.Sprintf("Could not update user: %s", err)})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	} else if isUserSelf { // if the user wants to update itself
		// Update the current user
		if admin.LabQuota.Valid {
			labQuota := admin.LabQuota.Int32
			req.LabQuota = &labQuota
		} else {
			req.LabQuota = nil
		}
		if err := d.updateAdminUserQuery(ctx, req, currUser, admin, isUserSelf); err != nil {
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
	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
	log.Debug().Msgf("admin claims: %v", admin)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("Username", username).
		Msg("AdminUser is trying to list a specific user")

	// Get the dbUser to return without showing the pw hash
	dbUser, err := d.db.GetAdminUserNoPwByUsername(ctx, username)
	if err != nil {
		log.Error().Err(err).Msg("Error getting admin user")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Could not find user"})
		return
	}
	perms, err := d.getDetailedUserPerms(dbUser.Username, dbUser.Organization)
	if err != nil {
		log.Error().Err(err).Msg("error getting implicit permissions for user")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}

	var labQuota *int32
	if !dbUser.LabQuota.Valid {
		labQuota = nil
	} else {
		labQuota = &dbUser.LabQuota.Int32
	}
	userToReturn := &AdminUserReponse{
		User: AdminUserNoPw{
			Username:     dbUser.Username,
			FullName:     dbUser.FullName,
			Email:        dbUser.Email,
			Role:         dbUser.Role,
			Organization: dbUser.Organization,
			LabQuota:     labQuota,
		},
		Perms: perms,
	}

	// Setting up casbin request
	sub := admin.Username
	dom := admin.Organization
	obj := fmt.Sprintf("users::%s", dbUser.Organization)
	act := "read"
	// Trying to authorize user
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing user read")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK", UserInfo: userToReturn})
		return
	} else if admin.Username == dbUser.Username {
		c.JSON(http.StatusOK, APIResponse{Status: "OK", UserInfo: userToReturn})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) getAdminUsers(c *gin.Context) {
	ctx := context.Background()

	// Unpack the jwt claims passed in the gin context to a struct
	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
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
	log.Debug().Msgf("Requests: %v", requests)
	// Trying to authorize user
	if authorized, err := d.enforcer.BatchEnforce(requests); authorized[0] || authorized[1] || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing users read")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		// Superuser
		if authorized[0] {
			users, err := d.db.GetAdminUsers(ctx, c.Query("organization"))
			if err != nil {
				log.Error().Err(err).Msg("Error getting admin users")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
				return
			}
			usersWithPerms := []AdminUserReponse{}
			for _, dbUser := range users {
				perms, err := d.getDetailedUserPerms(dbUser.Username, dbUser.Organization)
				if err != nil {
					log.Error().Err(err).Msg("error getting implicit permissions for user")
					c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
					return
				}
				var labQuota *int32
				if !dbUser.LabQuota.Valid {
					labQuota = nil
				} else {
					quota := dbUser.LabQuota.Int32
					labQuota = &quota
				}
				userToReturn := AdminUserReponse{
					User: AdminUserNoPw{
						Username:     dbUser.Username,
						FullName:     dbUser.FullName,
						Email:        dbUser.Email,
						Role:         dbUser.Role,
						Organization: dbUser.Organization,
						LabQuota:     labQuota,
					},
					Perms: perms,
				}
				usersWithPerms = append(usersWithPerms, userToReturn)
			}
			c.JSON(http.StatusOK, APIResponse{Status: "OK", Users: usersWithPerms})
			return
		} else if authorized[1] { // Some organisational user
			users, err := d.db.GetAdminUsers(ctx, admin.Organization)
			if err != nil {
				log.Error().Err(err).Msg("Error getting admin users")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
				return
			}
			usersWithPerms := []AdminUserReponse{}
			for _, dbUser := range users {
				perms, err := d.getDetailedUserPerms(dbUser.Username, dbUser.Organization)
				if err != nil {
					log.Error().Err(err).Msg("error getting implicit permissions for user")
					c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
					return
				}
				var labQuota *int32
				if !dbUser.LabQuota.Valid {
					labQuota = nil
				} else {
					quota := dbUser.LabQuota.Int32
					labQuota = &quota
				}
				userToReturn := AdminUserReponse{
					User: AdminUserNoPw{
						Username:     dbUser.Username,
						FullName:     dbUser.FullName,
						Email:        dbUser.Email,
						Role:         dbUser.Role,
						Organization: dbUser.Organization,
						LabQuota:     labQuota,
					},
					Perms: perms,
				}
				usersWithPerms = append(usersWithPerms, userToReturn)
			}
			c.JSON(http.StatusOK, APIResponse{Status: "OK", Users: usersWithPerms})
			return
		}
	}

	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) updateRole(c *gin.Context) {
	type roleUpdate struct {
		NewRole string `json:"newRole" binding:"required"`
	}
	var req roleUpdate
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}

	usernameToUpdate := c.Param("username")

	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("UserToChange", usernameToUpdate).
		Str("NewRole", req.NewRole).
		Msg("AdminUser is trying to change role of a user")

	if strings.EqualFold(admin.Username, usernameToUpdate) {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Cannot change own role"})
		return
	}

	userToUpdate, err := d.db.GetAdminUserByUsername(c, usernameToUpdate)
	if err != nil {
		log.Error().Err(err).Msg("Error getting user")
		c.JSON(http.StatusNotFound, APIResponse{Status: "Could not find user to update"})
		return
	}

	var requests = [][]interface{}{
		{admin.Username, admin.Organization, fmt.Sprintf("users::%s", userToUpdate.Organization), "write"},
		{admin.Username, admin.Organization, fmt.Sprintf("role::%s", req.NewRole), "write"},
	}
	if authorized, err := d.enforcer.BatchEnforce(requests); (authorized[0] && authorized[1]) || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing role update")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		if req.NewRole == "superadmin" && userToUpdate.Organization != "Admins" {
			c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized... Superadmins can only be added to the Admins organization"})
			return

		}

		changeApplied, err := d.enforcer.AddRoleForUser(userToUpdate.Username, fmt.Sprintf("role::%s", req.NewRole), userToUpdate.Organization)
		if err != nil {
			log.Error().Err(err).Msg("Error adding role")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		log.Debug().Msgf("Change applied: %v", changeApplied)

		if !changeApplied {
			c.JSON(http.StatusBadRequest, APIResponse{Status: "Role already assigned"})
			return
		}

		_, err = d.enforcer.DeleteRoleForUser(userToUpdate.Username, userToUpdate.Role, userToUpdate.Organization)
		if err != nil {
			log.Error().Err(err).Msg("Error deleting role")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		if err := d.db.UpdateAdminUserRoleByUsername(c, db.UpdateAdminUserRoleByUsernameParams{Role: fmt.Sprintf("role::%s", req.NewRole), Username: usernameToUpdate}); err != nil {
			log.Error().Err(err).Msg("Error updating role")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) updateUserOrganization(c *gin.Context) {
	type orgUpdate struct {
		NewOrganization string `json:"newOrganization" binding:"required"`
	}
	var req orgUpdate
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}

	usernameToUpdate := c.Param("username")

	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("UserToChange", usernameToUpdate).
		Str("NewOrganization", req.NewOrganization).
		Msg("AdminUser is trying to change organization of a user")

	if strings.EqualFold(admin.Username, usernameToUpdate) {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Cannot change own role"})
		return
	}

	userToUpdate, err := d.db.GetAdminUserByUsername(c, usernameToUpdate)
	if err != nil {
		log.Error().Err(err).Msg("Error getting user")
		c.JSON(http.StatusNotFound, APIResponse{Status: "Could not find user to update"})
		return
	}

	if userToUpdate.Role == "role::superadmin" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Cannot change organization of a superadmin"})
		return
	}

	if strings.EqualFold(userToUpdate.Organization, req.NewOrganization) {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "User already in that organization"})
		return
	}

	newOrganization, err := d.db.GetOrgByName(c, req.NewOrganization)
	if err != nil {
		log.Error().Err(err).Msg("Error getting organization")
		c.JSON(http.StatusNotFound, APIResponse{Status: "Could not find organization"})
		return
	}

	oldOrganization, err := d.db.GetOrgByName(c, userToUpdate.Organization)
	if err != nil {
		log.Error().Err(err).Msg("Error getting organization")
		c.JSON(http.StatusNotFound, APIResponse{Status: "Could not find organization"})
		return
	}

	if strings.EqualFold(userToUpdate.Username, oldOrganization.OwnerUser) {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Cannot change organization of a current organization owner"})
		return
	}

	sub := admin.Username
	dom := admin.Organization
	obj := "organizations"
	act := "write"
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing organization update")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		_, err := d.enforcer.AddRoleForUser(userToUpdate.Username, userToUpdate.Role, newOrganization.Name)
		if err != nil {
			log.Error().Err(err).Msg("Error adding role")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		_, err = d.enforcer.DeleteRoleForUser(userToUpdate.Username, userToUpdate.Role, userToUpdate.Organization)
		if err != nil {
			log.Error().Err(err).Msg("Error deleting role")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		if err := d.db.UpdateAdminUserOrganizationByUsername(c, db.UpdateAdminUserOrganizationByUsernameParams{Organization: newOrganization.Name, Username: userToUpdate.Username}); err != nil {
			log.Error().Err(err).Msg("Error updating organization")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
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
	labQuota := sql.NullInt32{Valid: false}
	if user.LabQuota != nil {
		labQuota = sql.NullInt32{Valid: true, Int32: *user.LabQuota}
	}
	if user.Role != "npuser" {
		labQuota = sql.NullInt32{Valid: false}
	}
	// Passing request data to query param struct
	newUser := db.CreateAdminUserParams{
		Username:     user.Username,
		Password:     string(pwHash),
		FullName:     user.FullName,
		Email:        user.Email,
		Role:         fmt.Sprintf("role::%s", user.Role),
		Organization: org,
		LabQuota:     labQuota,
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
func (d *daemon) updateAdminUserQuery(ctx context.Context, updatedUser adminUserRequest, currUser db.AdminUser, admin AdminClaims, isUpdatedUserSelf bool) error {
	// Get admininfo for password verification to prevent unauthorized updates of users
	adminInfo, err := d.db.GetAdminUserByUsername(ctx, admin.Username)
	if err != nil {
		return err
	}

	// When changing password we want to make sure that the user knows the current password
	match := verifyPassword(adminInfo.Password, updatedUser.VerifyAdminPassword)
	// Update password if changed
	if !verifyPassword(currUser.Password, updatedUser.Password) && updatedUser.Password != "" && (match || !isUpdatedUserSelf) {
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
		newPw := db.UpdateAdminPasswordParams{
			Password: string(newPwHash),
			Username: updatedUser.Username,
		}
		// Update the password
		if err := d.db.UpdateAdminPassword(ctx, newPw); err != nil {
			return fmt.Errorf("Error updating password: %s", err)
		}
	} else if updatedUser.Password != "" && !match && !verifyPassword(currUser.Password, updatedUser.Password) {
		return errors.New("Wrong password")
	}

	// Update email if changed
	if updatedUser.Email != currUser.Email && updatedUser.Email != "" {
		log.Debug().Msg("Updating email")
		// Pass the email and user to update into the query param struct
		newEmail := db.UpdateAdminEmailParams{
			Email:    updatedUser.Email,
			Username: updatedUser.Username,
		}
		// Update the email
		if err := d.db.UpdateAdminEmail(ctx, newEmail); err != nil {
			return fmt.Errorf("Error updating email: %s", err)
		}
	}

	labQuota := sql.NullInt32{Valid: false}
	if updatedUser.LabQuota != nil {
		labQuota = sql.NullInt32{Valid: true, Int32: *updatedUser.LabQuota}
	}
	newLabQuota := db.UpdateAdminLabQuotaParams{
		Labquota: labQuota,
		Username: updatedUser.Username,
	}
	if err := d.db.UpdateAdminLabQuota(ctx, newLabQuota); err != nil {
		return fmt.Errorf("Error updating labQuota: %s", err)
	}

	return nil
}

func (d *daemon) getDetailedUserPerms(username, userorg string) (map[string]string, error) {
	perms, err := d.enforcer.GetImplicitPermissionsForUser(username, userorg)
	if err != nil {
		log.Error().Err(err).Msg("error getting implicit permissions for user")
		return nil, err
	}
	permsToReturn := make(map[string]string)
	for _, p := range perms {
		// index 2 holds the object and index 3 holds the accessRights
		object := strings.Split(p[2], "::")[0]

		if object == "objects" {
			// gets the children object of the object group policy
			detailedPerms := d.enforcer.GetFilteredNamedGroupingPolicy("g2", 1, p[2])
			for _, perm := range detailedPerms {
				object = strings.Split(perm[0], "::")[0]
				permsToReturn[object] = p[3]
			}
			continue
		}
		accessRights := p[3]
		permsToReturn[object] = accessRights
	}

	return permsToReturn, nil
}
