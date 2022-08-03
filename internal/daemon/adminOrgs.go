package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/database"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (d *daemon) adminorgSubrouter(r *gin.RouterGroup) {
	org := r.Group("/orgs")
	org.Use(corsMiddleware())
	org.Use(d.adminAuthMiddleware())

	org.POST("", d.newOrganization)
	org.GET("", d.listOrganizations)
	org.PUT("", d.updateOrganization)
	org.DELETE("", d.deleteOrganization)

}

type adminOrgRequest struct {
	OrgName  string           `json:"org_name"`
	OrgOwner adminUserRequest `json:"org_owner"`
}

var orgCreationPolicies = [][]string{
	{"role::superadmin", "org::", "objects::", "(read|write)"},
	{"role::administrator", "org::", "objects::", "(read|write)"},
	{"role::developer", "org::", "events::", "(read|write)"},
	{"role::developer", "org::", "exdbs::", "(read|write)"},
	{"role::developer", "org::", "registries::", "(read|write)"},
	{"role::developer", "org::", "secretchals::", "(read|write)"},
	{"role::developer", "org::", "users::", "read"},
	{"role::user", "org::", "users::", "(read|write)"},
	{"role::user", "org::", "events::", "(read|write)"},
	{"role::user", "org::", "role::user", "(read|write)"},
	{"role::user", "org::", "role::npuser", "(read|write)"},
	{"role::npuser", "org::", "events::", "(read|write)"},
}

// g2 policies
var orgCreationGroupPolicies = [][]string{
	{"events::", "objects::"},
	{"roles::", "objects::"},
	{"exdbs::", "objects::"},
	{"registries::", "objects::"},
	{"users::", "objects::"},
	{"secretchals::", "objects::"},
	{"role::administrator", "roles::"},
	{"role::developer", "roles::"},
	{"role::user", "roles::"},
	{"role::npuser", "roles::"},
}

// g3 policies
var orgCreationDomainHirachyPolicy = []string{"org::Admins", ""}

func (d *daemon) newOrganization(c *gin.Context) {
	ctx := context.Background()
	// Unpack user request into go struct
	var req adminOrgRequest
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
		Str("NewOrg", req.OrgName).
		Msg("Trying to create a new organization")

	// Setup casbin request
	sub := admin.Username
	dom := admin.Organization
	obj := "organizations"
	act := "write"
	log.Debug().Str("sub", sub).Str("dom", dom).Str("obj", obj).Msg("Admin")
	if err := d.enforcer.LoadPolicy(); err != nil {
		log.Error().Err(err).Msgf("Error loading policies")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}
	// Check if subject has access to write to organizations
	if authorized, err := d.enforcer.Enforce(sub, dom, obj, act); authorized || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		if err := d.creatOrgWithAdmin(ctx, req.OrgName, req.OrgOwner); err != nil {
			log.Error().Err(err).Msg("Error creating organization with admin")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: fmt.Sprintf("Error creating organization with admin: %v", err)})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// TODO Will add these functionalities after finishing users enpoints
func (d *daemon) listOrganizations(c *gin.Context) {

}

func (d *daemon) updateOrganization(c *gin.Context) {

}

func (d *daemon) deleteOrganization(c *gin.Context) {

}

func (d *daemon) creatOrgWithAdmin(ctx context.Context, org string, admin adminUserRequest) error {
	orgExists, err := d.db.CheckIfOrgExists(ctx, org)
	if err != nil {
		return err
	}
	userExists, err := d.db.CheckIfUserExists(ctx, admin.Username)
	if err != nil {
		return err
	}
	if orgExists || userExists {
		if userExists {
			return errors.New(userExistsError)
		}
		return errors.New(orgExistsError)
	}
	if len(admin.Password) < 8 {
		return errors.New(passwordTooShortError)
	}
	// insert org and user into db
	orgParams := database.AddOrganizationParams{
		Org:           fmt.Sprintf("org::%s", org),
		Ownerusername: admin.Username,
		Owneremail:    admin.Email,
	}
	if err := d.db.AddOrganization(ctx, orgParams); err != nil {
		return err
	}

	admin.Role = "administrator"
	if _, err := d.createAdminUser(ctx, admin, orgParams.Org); err != nil {
		return err
	}

	if err := d.addOrgPolicies(org); err != nil {
		return err
	}
	return nil
}

func (d *daemon) addOrgPolicies(org string) error {
	regex, err := regexp.Compile("(^.*::$)")
	if err != nil {
		return err
	}
	// Populate policies with organization
	var policies [][]string
	policies = append(policies, orgCreationPolicies...)
	for i := 0; i < len(policies); i++ {
		for j := 0; j < len(policies[i]); j++ {
			if regex.MatchString(policies[i][j]) {
				policies[i][j] = fmt.Sprintf("%s%s", policies[i][j], org)
			}
		}
	}
	if _, err := d.enforcer.AddPolicies(policies); err != nil {
		return err
	}

	// Populate groups with organization
	var groups [][]string
	groups = append(groups, orgCreationGroupPolicies...)
	for i := 0; i < len(groups); i++ {
		for j := 0; j < len(groups[i]); j++ {
			if regex.MatchString(groups[i][j]) {
				groups[i][j] = fmt.Sprintf("%s%s", groups[i][j], org)
			}
		}
	}
	// Add groups to casbin
	if _, err := d.enforcer.AddNamedGroupingPolicies("g2", groups); err != nil {
		return err
	}

	// Add domain to Admins domain in casbin
	orgCreationDomainHirachyPolicy[1] = fmt.Sprintf("org::%s", org)
	if _, err := d.enforcer.AddNamedGroupingPolicy("g3", orgCreationDomainHirachyPolicy); err != nil {
		return err
	}
	return nil
}
