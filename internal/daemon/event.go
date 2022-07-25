package daemon

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (d *daemon) eventSubrouter(r *gin.RouterGroup) {
	//gtaAPI := r.Group("/gta")
	//gtaAPI.Use(tokenAuthMiddleware())

	// Gm user management
	r.GET("/", d.testHandlerTwo)

}

func (d *daemon) testHandlerTwo(c *gin.Context) {
	c.JSON(http.StatusOK, APIResponse{Status: "OK"})
}
