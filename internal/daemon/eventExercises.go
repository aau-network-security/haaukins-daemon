package daemon

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/db"
	"github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (d *daemon) eventExercisesSubrouter(r *gin.RouterGroup) {
	exercises := r.Group("/exercises")

	exercises.Use(d.eventAuthMiddleware())

	exercises.GET("", d.getEventExercises)
	exercises.GET("/:status", d.getExercisesByStatus)

	exercises.POST("/solve", d.solveExercise)

	exercises.POST("/add/:exerciseTag", d.addExerciseToLab)
	exercises.POST("/stop/:exerciseTag", d.stopExercise)
	exercises.POST("/start/:exerciseTag", d.startExercise)
	exercises.POST("/reset/:exerciseTag", d.resetExercise)
}

type EventExercisesResponse struct {
	Categories []Category `json:"categories"`
}



// Get all exercises for event that the requesting team belongs to
// Depending if the event has dynamic scoring enabled, it will inject the points into the
// child exercise objects accordingly
func (d *daemon) getEventExercises(c *gin.Context) {
	ctx := context.Background()

	teamClaims := unpackTeamClaims(c)

	dbEvent, err := d.db.GetEventByTag(ctx, teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("error getting event from database")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}

	getTeamParams := db.GetTeamFromEventByUsernameParams{
		Username: teamClaims.Username,
		Eventid:  dbEvent.ID,
	}
	dbTeam, err := d.db.GetTeamFromEventByUsername(ctx, getTeamParams)
	if err != nil {
		log.Error().Err(err).Msg("error getting team from database")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}

	event, err := d.eventpool.GetEvent(teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("could not find event in event pool")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "event for team is not currently running"})
		return
	}

	exercisesFromExService, err := d.exClient.GetExerciseByTags(ctx, &proto.GetExerciseByTagsRequest{Tag: event.Config.ExerciseTags})
	if err != nil {
		log.Error().Err(err).Msg("error getting exercise by tags from exercise service")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}

	categoriesFromExService, err := d.exClient.GetCategories(ctx, &proto.Empty{})
	if err != nil {
		log.Error().Err(err).Msg("error getting categories from exercise service")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}

	// For dynamic scoring if enabled
	solvesMap, err := d.db.GetEventSolvesMap(ctx, dbEvent.ID)
	if err != nil {
		log.Error().Err(err).Msg("error getting event solves map from database")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}

	teamSolves, err := d.db.GetTeamSolvesMap(ctx, dbTeam.ID)
	if err != nil {
		log.Error().Err(err).Msg("error getting team solves database")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}

	// TODO return amount of solves of challenge as well
	eventExercisesResponse := &EventExercisesResponse{
		Categories: []Category{},
	}

	for _, exServiceCategory := range categoriesFromExService.Categories {
		var exercises []Exercise
		for _, exServiceExercise := range exercisesFromExService.Exercises {
			for _, instance := range exServiceExercise.Instance {
			Inner:
				for _, childExercise := range instance.Children {
					if childExercise.Category != exServiceCategory.Name {
						continue Inner
					}

					solves := []Solve{}
					for _, dbSolve := range solvesMap[childExercise.Tag] {
						solve := Solve{
							Date: dbSolve.Date.Format(time.RFC822),
							Team: dbSolve.Username,
						}
						solves = append(solves, solve)
					}

					solvedByTeam, ok := teamSolves[childExercise.Tag]
					if !ok {
						solvedByTeam = false
					}

					var points int = int(childExercise.Points)
					if event.Config.DynamicScoring {
						points = calculateScore(event.Config, float64(len(solvesMap[childExercise.Tag])))
					}

					safeHtml, err := sanitizeUnsafeMarkdown([]byte(childExercise.TeamDescription))
					if err != nil {
						log.Error().Msgf("Error converting to commonmark: %s", err)
					}

					exercise := Exercise{
						ParentExerciseTag: exServiceExercise.Tag,
						Static:            exServiceExercise.Static,
						Name:              childExercise.Name,
						Tag:               childExercise.Tag,
						Points:            points,
						Category:          childExercise.Category,
						Description:       string(safeHtml),
						Solved:            solvedByTeam,
						Solves:            solves,
					}
					exercises = append(exercises, exercise)
				}
			}
		}
		if len(exercises) == 0 {
			continue
		}
		category := Category{
			Name:      exServiceCategory.Name,
			Exercises: exercises,
		}
		eventExercisesResponse.Categories = append(eventExercisesResponse.Categories, category)
	}

	c.JSON(http.StatusOK, APIResponse{Status: "OK", EventExercises: eventExercisesResponse})
}

// Returns a list of currently running exercises for a team
func (d *daemon) getExercisesByStatus(c *gin.Context) {

}

type SolveExerciseRequest struct {
	ParentTag string `json:"parentTag"`
	Tag       string `json:"tag"`
	Flag      string `json:"flag"`
}

// Uses the flag provided by a team to determine if an exercise has been successfully solved
// Adds the exercise tag and solve at timestamp to db if successful
func (d *daemon) solveExercise(c *gin.Context) {
	ctx := context.Background()

	var req SolveExerciseRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Error"})
		return
	}

	teamClaims := unpackTeamClaims(c)

	event, err := d.eventpool.GetEvent(teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("error getting event from event pool")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}

	team, err := event.GetTeam(teamClaims.Username)
	if err != nil {
		log.Error().Err(err).Msg("error getting team from event")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}

	dbEvent, err := d.db.GetEventByTag(ctx, teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("error getting event from database")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}

	getTeamParam := db.GetTeamFromEventByUsernameParams{
		Username: teamClaims.Username,
		Eventid:  dbEvent.ID,
	}
	dbTeam, err := d.db.GetTeamFromEventByUsername(ctx, getTeamParam)
	if err != nil {
		log.Error().Err(err).Msg("error getting team for event from database")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}

	exClientResp, err := d.exClient.GetExerciseByTags(ctx, &proto.GetExerciseByTagsRequest{Tag: []string{req.ParentTag}})
	if err != nil {
		log.Error().Err(err).Msg("error getting exercise from exercise service")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}

	if exClientResp.Exercises[0].Static {
		for _, instance := range exClientResp.Exercises[0].Instance {
			for _, childExercise := range instance.Children {
				staticFlag := strings.Trim(childExercise.Static, " ")
				if childExercise.Tag == req.Tag && staticFlag == strings.Trim(req.Flag, " ") {
					addSolveParams := db.AddSolveForTeamInEventParams{
						Tag:      req.Tag,
						Eventid:  dbEvent.ID,
						Teamid:   dbTeam.ID,
						Solvedat: time.Now(),
					}
					if err := d.db.AddSolveForTeamInEvent(ctx, addSolveParams); err != nil {
						log.Error().Err(err).Msg("error adding solve to database")
						c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
						return
					}
					c.JSON(http.StatusOK, APIResponse{Status: "OK"})
					return
				}
			}
		}
		c.JSON(http.StatusBadRequest, APIResponse{Status: "wrong flag"})
		return
	}

	if team.Lab != nil {
		for _, exercise := range team.Lab.LabInfo.Exercises {
			for _, childExercise := range exercise.ChildExercises {
				if childExercise.Tag == req.Tag {
					flag := strings.Trim(childExercise.Flag, " ")
					if flag == strings.Trim(req.Flag, " ") {
						addSolveParams := db.AddSolveForTeamInEventParams{
							Tag:      req.Tag,
							Eventid:  dbEvent.ID,
							Teamid:   dbTeam.ID,
							Solvedat: time.Now(),
						}
						if err := d.db.AddSolveForTeamInEvent(ctx, addSolveParams); err != nil {
							log.Error().Err(err).Msg("error adding solve to database")
							c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
							return
						}
						c.JSON(http.StatusOK, APIResponse{Status: "OK"})
						return
					} else {
						c.JSON(http.StatusBadRequest, APIResponse{Status: "wrong flag"})
						return
					}
				}
			}
		}
		c.JSON(http.StatusBadRequest, APIResponse{Status: "exercise not added to lab"})
		return
	}
	c.JSON(http.StatusBadRequest, APIResponse{Status: "configure lab and add exercise before solving this challenge"})
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
