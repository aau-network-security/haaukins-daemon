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
)

func (d *daemon) adminOrgSubrouter(r *gin.RouterGroup) {
	org := r.Group("/orgs")
	org.Use(d.adminAuthMiddleware())

	org.POST("", d.newOrganization)
	org.GET("", d.listOrganizations)
	org.PUT("", d.updateOrganization)
	org.DELETE("/:org", d.deleteOrganization)

}

type adminOrgRequest struct {
	OrgName  string           `json:"orgName"`
	LabQuota *int32           `json:"labQuota,omitempty"`
	OrgOwner adminUserRequest `json:"orgOwner"`
}

var orgCreationPolicies = [][]string{
	{"role::superadmin", "", "objects::", "(read|write)"},
	{"role::administrator", "", "objects::", "(read|write)"},
	{"role::developer", "", "events::", "(read|write)"},
	{"role::developer", "", "secretchals::", "(read|write)"},
	{"role::developer", "", "exercises::", "(read|write)"},
	{"role::developer", "", "challengeProfiles::", "(read|write)"},
	// {"role::developer", "", "users::", "read"},
	// {"role::user", "", "users::", "(read|write)"},
	{"role::user", "", "events::", "(read|write)"},
	{"role::user", "", "exercises::", "read"},
	{"role::user", "", "challengeProfiles::", "(read|write)"},
	// {"role::user", "", "role::user", "(read|write)"},
	// {"role::user", "", "role::npuser", "(read|write)"},
	{"role::npuser", "", "events::", "(read|write)"},
	{"role::npuser", "", "exercises::", "read"},
	{"role::npuser", "", "challengeProfiles::", "read"},
}

// g2 policies
var orgCreationGroupPolicies = [][]string{
	{"events::", "objects::"},
	{"notOwnedEvents::", "objects::"},
	{"roles::", "objects::"},
	{"users::", "objects::"},
	{"secretchals::", "objects::"},
	{"exercises::", "objects::"},
	{"challengeProfiles::", "objects::"},
	{"role::administrator", "roles::"},
	{"role::developer", "roles::"},
	{"role::user", "roles::"},
	{"role::npuser", "roles::"},
}

// g3 policies
var orgCreationDomainHirachyPolicy = []string{"Admins", ""}

// TODO Add email func to send randomly generated password if password is set to blank for new user
func (d *daemon) newOrganization(c *gin.Context) {
	ctx := context.Background()
	// Unpack user request into go struct
	var req adminOrgRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}

	// Validate username
	if req.OrgName == "" || strings.Trim(req.OrgName, " ") == "" {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Invalid orgname"})
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
		Str("NewOrg", req.OrgName).
		Msg("Trying to create a new organization")

	// Setup casbin request
	sub := admin.Username
	dom := admin.Organization
	obj := "organizations"
	act := "write"
	log.Debug().Str("sub", sub).Str("dom", dom).Str("obj", obj).Msg("Admin")
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing create organization")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		if err := d.creatOrgWithAdmin(ctx, req); err != nil {
			log.Error().Err(err).Msg("Error creating organization with admin")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("Error creating organization with admin: %v", err)})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) listOrganizations(c *gin.Context) {
	ctx := context.Background()
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
		Msg("Trying to list all organizations")

	// Setup casbin request
	sub := admin.Username
	dom := admin.Organization
	obj := "organizations"
	act := "read"
	// Check if subject has access to read to organizations
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing list organizations")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		dbOrgs, err := d.db.GetOrganizations(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Error listing organizations")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("Error listing organizations: %v", err)})
			return
		}
		orgs := []Organization{}
		for _, dbOrg := range dbOrgs {
			org := Organization{
				ID:         dbOrg.ID,
				Name:       dbOrg.Name,
				OwnerUser:  dbOrg.OwnerUser,
				OwnerEmail: dbOrg.OwnerEmail,
			}
			if !dbOrg.LabQuota.Valid {
				org.LabQuota = nil
			} else {
				labQuota := dbOrg.LabQuota.Int32
				org.LabQuota = &labQuota
			}
			orgs = append(orgs, org)
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK", Orgs: orgs})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) updateOrganization(c *gin.Context) {
	ctx := context.Background()
	// Unpack user request into go struct
	var req adminOrgRequest
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
		Str("Org", req.OrgName).
		Msg("Trying to update  an organization")

	// Setup casbin request
	sub := admin.Username
	dom := admin.Organization
	obj := "organizations"
	act := "write"
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing update organizations")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		if err := d.checkAndApplyUpdates(ctx, req); err != nil {
			log.Error().Err(err).Msgf("Encountered an error while updating organizations")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("%s", err)})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) deleteOrganization(c *gin.Context) {
	ctx := context.Background()
	orgName := c.Param("org")

	// Make sure they are not able to delete the root organization
	if strings.ToLower(orgName) == "admins" {
		log.Warn().Msg("User tried to delete root organization")
		c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
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
		Str("NewOrg", orgName).
		Msg("Trying to create a new organization")

	// Setup casbin request
	sub := admin.Username
	dom := admin.Organization
	obj := "organizations"
	act := "write"
	// Authorizing org deletion
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing delete organizations")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		if err := d.deleteOrgAndPolicies(ctx, orgName); err != nil {
			log.Error().Err(err).Msgf("Encountered an error while deleting organizations")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("%s", err)})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) deleteOrgAndPolicies(ctx context.Context, orgName string) error {
	orgExists, err := d.db.CheckIfOrgExists(ctx, orgName)
	if err != nil {
		return err
	}
	if !orgExists {
		return errors.New("org you wish to delete does not exist")
	}

	orgToDelete, err := d.db.GetOrgByName(ctx, orgName)
	if err != nil {
		return err
	}
	// First delete the organization from the database
	if err := d.db.DeleteOrganization(ctx, orgName); err != nil {
		return err
	}

	// Delete policies and grouping policies including all users linked to the organization
	if _, err = d.enforcer.DeleteDomains(orgToDelete.Name); err != nil {
		return err
	}

	groups, err := assemblePolicies(orgCreationGroupPolicies, orgToDelete.Name)
	if err != nil {
		return err
	}
	if _, err := d.enforcer.RemoveNamedGroupingPolicies("g2", groups); err != nil {
		return err
	}

	orgCreationDomainHirachyPolicy[1] = orgToDelete.Name
	if _, err := d.enforcer.RemoveNamedGroupingPolicy("g3", orgCreationDomainHirachyPolicy); err != nil {
		return err
	}

	return nil
}

func (d *daemon) checkAndApplyUpdates(ctx context.Context, updatedOrg adminOrgRequest) error {
	orgExists, err := d.db.CheckIfOrgExists(ctx, updatedOrg.OrgName)
	if err != nil {
		return err
	}

	// Make sure the new user actually is linked to the organization
	checkExistsParams := db.CheckIfUserExistsInOrgParams{
		Username:     updatedOrg.OrgOwner.Username,
		Organization: updatedOrg.OrgName,
	}
	userExists, err := d.db.CheckIfUserExistsInOrg(ctx, checkExistsParams)
	if err != nil {
		return err
	}

	if !orgExists || !userExists {
		if !orgExists {
			return errors.New("org you wish to update does not exist")
		}
		return errors.New("user you wish to bind to org, does not exist within organization")
	}
	newOwner, err := d.db.GetAdminUserByUsername(ctx, updatedOrg.OrgOwner.Username)
	if err != nil {
		return err
	}
	// Is the new owner even an administrator?
	if newOwner.Role != "role::administrator" {
		return errors.New("user is not an administrator and can therefore not become an organization owner")
	}

	labQuota := sql.NullInt32{Valid: false}
	if updatedOrg.LabQuota != nil {
		labQuota = sql.NullInt32{Valid: true, Int32: *updatedOrg.LabQuota}
	}

	//Update the organization if all checks has passed
	updateParams := db.UpdateOrganizationParams{
		Ownerusername: newOwner.Username,
		Owneremail:    newOwner.Email,
		Orgname:       updatedOrg.OrgName,
		Labquota:      labQuota,
	}
	if err := d.db.UpdateOrganization(ctx, updateParams); err != nil {
		return err
	}
	return nil
}

func (d *daemon) creatOrgWithAdmin(ctx context.Context, newOrg adminOrgRequest) error {

	// Make sure the organization and user does not currently exist
	orgExists, err := d.db.CheckIfOrgExists(ctx, newOrg.OrgName)
	if err != nil {
		return err
	}
	userExists, err := d.db.CheckIfUserExists(ctx, newOrg.OrgOwner.Username)
	if err != nil {
		return err
	}
	if orgExists || userExists {
		if userExists {
			return errors.New(userExistsError)
		}
		return errors.New(orgExistsError)
	}

	// Check owners password length
	if len(newOrg.OrgOwner.Password) < 8 {
		return errors.New(passwordTooShortError)
	}

	labQuota := sql.NullInt32{Valid: false}
	if newOrg.LabQuota != nil {
		labQuota = sql.NullInt32{Valid: true, Int32: *newOrg.LabQuota}
	}

	// insert org and user into db
	orgParams := db.AddOrganizationParams{
		Org:           newOrg.OrgName,
		Ownerusername: newOrg.OrgOwner.Username,
		Owneremail:    newOrg.OrgOwner.Email,
		Labquota:      labQuota,
	}
	if err := d.db.AddOrganization(ctx, orgParams); err != nil {
		return err
	}

	newOrg.OrgOwner.Role = "administrator"
	if _, err := d.createAdminUser(ctx, newOrg.OrgOwner, orgParams.Org); err != nil {
		return err
	}

	if err := d.addOrgPolicies(newOrg.OrgName); err != nil {
		return err
	}
	return nil
}

func (d *daemon) addOrgPolicies(org string) error {

	// Populate policies with organization where string matches regex ex. "users::"
	policies, err := assemblePolicies(orgCreationPolicies, org)
	if err != nil {
		return err
	}
	if _, err := d.enforcer.AddPolicies(policies); err != nil {
		return err
	}

	// Populate groups with organization
	groups, err := assemblePolicies(orgCreationGroupPolicies, org)
	if err != nil {
		return err
	}
	// Add groups to casbin
	if _, err := d.enforcer.AddNamedGroupingPolicies("g2", groups); err != nil {
		return err
	}

	// Add domain to Admins domain in casbin
	orgCreationDomainHirachyPolicy[1] = org
	if _, err := d.enforcer.AddNamedGroupingPolicy("g3", orgCreationDomainHirachyPolicy); err != nil {
		return err
	}
	return nil
}
