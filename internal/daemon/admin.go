package daemon

import (
	"github.com/gin-gonic/gin"
)

func (d *daemon) adminSubrouter(r *gin.RouterGroup) {
	user := r.Group("/user")
	d.adminUserSubrouter(user)

}
