package daemon

import (
	"github.com/gin-gonic/gin"
)

func (dh *dbHandler) eventSubrouter(r *gin.RouterGroup) {
	//gtaAPI := r.Group("/gta")
	//gtaAPI.Use(tokenAuthMiddleware())

	// Gm user management
	r.POST("/", dh.testHandlerTwo)

}

func (dh *dbHandler) testHandlerTwo(c *gin.Context) {

}
