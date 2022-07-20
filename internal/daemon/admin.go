package daemon

import (
	"github.com/gin-gonic/gin"
)

func (dh *dbHandler) adminSubrouter(r *gin.RouterGroup) {
	//gtaAPI := r.Group("/gta")
	//gtaAPI.Use(tokenAuthMiddleware())

	// Gm user management
	r.POST("/", dh.testHandler)

}

func (dh *dbHandler) testHandler(c *gin.Context) {

}
