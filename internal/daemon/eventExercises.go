package daemon

import "github.com/gin-gonic/gin"

func (d *daemon) eventExercisesSubrouter(r *gin.RouterGroup) {
	exercises := r.Group("/exercises")

	exercises.Use(d.eventAuthMiddleware())
	
	exercises.GET("/", d.getEventExercises)
	exercises.GET("/:status", d.getExercisesByStatus)
	
	exercises.POST("/solve", d.solveExercise)

	exercises.POST("/add/:exerciseTag", d.addExerciseToLab)
	exercises.POST("/stop/:exerciseTag", d.stopExercise)
	exercises.POST("/start/:exerciseTag", d.startExercise)
	exercises.POST("/reset/:exerciseTag", d.resetExercise)
}

// Get all exercises for event that the requesting team belongs to
func (d *daemon) getEventExercises(c *gin.Context) {

}

// Returns a list of currently running exercises for a team
func (d *daemon) getExercisesByStatus(c *gin.Context) {

}



// Uses the flag provided by a team to determine if an exercise has been successfully solved
// Adds the exercise tag and solve at timestamp to db if successful
func (d *daemon) solveExercise(c *gin.Context) {

}

// For teams to add an exercise which is not currently in the lab (advanced events only)
// Only a specific amount of exercises can be started at a time
// Will stop an arbitrary exercise if team has not explicitly requested a specific exercise to be replaced with
func (d *daemon) addExerciseToLab(c *gin.Context) {

}

// Starts an exercise which is currently stopped in a lab
// Only a specific amount of exercises can be started at a time
// Will stop an arbitrary exercise if team has not explicitly requested a specific exercise to be replaced with
func (d *daemon) startExercise(c *gin.Context) {

}

// Will stop a requested exercise for a team
func (d *daemon) stopExercise(c *gin.Context) {

}

// Used by teams to reset specific exercise containers
func (d *daemon) resetExercise(c *gin.Context) {

}

