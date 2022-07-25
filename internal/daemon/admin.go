package daemon

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (d *daemon) adminSubrouter(r *gin.RouterGroup) {
	//gtaAPI := r.Group("/gta")
	//gtaAPI.Use(tokenAuthMiddleware())

	// Gm user management
	r.GET("/", d.testHandler)

}

func (d *daemon) testHandler(c *gin.Context) {
	c.JSON(http.StatusOK, APIResponse{Status: "OK"})
}
