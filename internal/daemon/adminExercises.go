package daemon

import "github.com/gin-gonic/gin"

func (d *daemon) exerciseSubrouter(r *gin.RouterGroup) {
	exercises := r.Group("/exercises")
	
	exercises.Use(d.adminAuthMiddleware())
	exercises.GET("", d.getExercises)
	exercises.GET("/categories", d.getExerciseCategories)
	
	

}

func (d *daemon) getExercises(c *gin.Context) {

}

func (d *daemon) getExerciseCategories(c *gin.Context) {

}



