package daemon

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (d *daemon) eventSubrouter(r *gin.RouterGroup) {
	events := r.Group("/events")
	

	
	events.Use(d.adminAuthMiddleware())
	// CRUD
	events.POST("/", d.newEvent)
	events.GET("/", d.getEvents)

	// Additional routes
	events.POST("/exercise/add", d.addExerciseToEvent)
	events.POST("/exercise/reset", d.resetExerciseInEvent)
}

func (d *daemon) newEvent(c *gin.Context) {
	c.JSON(http.StatusOK, APIResponse{Status: "OK"})
}

func (d *daemon) getEvents(c *gin.Context) {

}

func (d *daemon) addExerciseToEvent(c *gin.Context) {

}

func (d *daemon) resetExerciseInEvent(c *gin.Context) {

}