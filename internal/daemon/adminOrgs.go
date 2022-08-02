package daemon

import "github.com/gin-gonic/gin"

func (d *daemon) adminorgSubrouter(r *gin.RouterGroup) {
	org := r.Group("/orgs")
	org.Use(corsMiddleware())
	org.Use(d.adminAuthMiddleware())

	org.POST("", d.newOrganization)
	org.GET("", d.listOrganizations)
	org.PUT("", d.updateAdminUser)
	org.DELETE("", d.deleteAdminUser)

}

func (d *daemon) newOrganization(r *gin.Context) {

}

func (d *daemon) listOrganizations(r *gin.Context) {

}

func (d *daemon) updateAdminUser(r *gin.Context) {

}

func (d *daemon) deleteAdminUser(r *gin.Context) {

}
