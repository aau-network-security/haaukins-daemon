package daemon

import (
	"github.com/gin-gonic/gin"
)

func (d *daemon) adminSubrouter(r *gin.RouterGroup) {
	d.adminUserSubrouter(r)
	d.adminOrgSubrouter(r)
	d.adminAgentsSubrouter(r)
	d.adminEventSubrouter(r)
	d.adminExerciseSubrouter(r)
}

func (d *daemon) eventSubrouter(r *gin.RouterGroup) {
	d.eventTeamSubrouter(r)
	d.eventLabsSubrouter(r)
}
