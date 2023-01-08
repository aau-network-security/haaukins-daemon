package daemon

import "github.com/gin-gonic/gin"

func (d *daemon) eventLabsSubrouter(r *gin.RouterGroup) {
	labs := r.Group("/labs")

	labs.Use(d.eventAuthMiddleware())
	labs.POST("/", d.configureLab)
	labs.GET("/", d.getLab)
	labs.GET("/resetlab", d.resetLab)
	labs.GET("/resetvm", d.resetVm)
}

// Used by teams who have not yet configured their lab lab (advanced events only)
func (d *daemon) configureLab(c *gin.Context) {

}

// Gets lab info for the requesting team
func (d *daemon) getLab(c *gin.Context) {

}

// Can be used by teams to completely reset their lab
func (d *daemon) resetLab(c *gin.Context) {

}

// Resets the connected VM in a teams lab in case of problems like freezing etc.
func (d *daemon) resetVm(c *gin.Context) {

}
