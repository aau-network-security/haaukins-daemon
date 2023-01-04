package daemon

import "github.com/gin-gonic/gin"

func (d *daemon) eventSubrouter(r *gin.RouterGroup) {
	d.eventTeamSubrouter(r)
}