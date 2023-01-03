package daemon

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (d *daemon) adminExerciseSubrouter(r *gin.RouterGroup) {
	// Exercises
	exercises := r.Group("/exercises")

	exercises.Use(d.adminAuthMiddleware())
	exercises.GET("", d.getExercises)
	exercises.GET("/categories", d.getExerciseCategories)

	// Exercise profiles
	profiles := exercises.Group("/profiles")

	profiles.POST("", d.addProfile)
	profiles.GET("", d.getProfiles)
	profiles.PUT("", d.updateProfile)
	profiles.DELETE("/:profile", d.deleteProfile)
}

// TODO remember exercise profiles here
func (d *daemon) getExercises(c *gin.Context) {
	eventConf := EventConfig{
		DynamicMax:            2000,
		DynamicMin:            50,
		DynamicSolveThreshold: 200,
	}
	c.JSON(http.StatusOK, getScore(eventConf, 50))
}

func (d *daemon) getExerciseCategories(c *gin.Context) {

}

func (d *daemon) addProfile(c *gin.Context) {

}

func (d *daemon) updateProfile(c *gin.Context) {

}

func (d *daemon) deleteProfile(c *gin.Context) {

}

func (d *daemon) getProfiles(c *gin.Context) {

}
