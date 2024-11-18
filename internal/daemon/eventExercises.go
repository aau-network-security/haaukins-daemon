package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/aau-network-security/haaukins-daemon/internal/db"
	"github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
)

func (d *daemon) eventExercisesSubrouter(r *gin.RouterGroup) {
	exercises := r.Group("/exercises")

	exercises.Use(d.eventAuthMiddleware())

	exercises.GET("", d.getEventExercises)
	exercises.GET("/:status", d.getExercisesByStatus)

	exercises.POST("/solve", d.solveExercise)

	exercises.PUT("/start/:exerciseTag", d.startExerciseInLab)
	exercises.PUT("/stop/:exerciseTag", d.stopExercise)
	//exercises.PUT("/start/:exerciseTag", d.startExercise)
	exercises.PUT("/reset/:exerciseTag", d.resetExercise)
}

type EventExercisesResponse struct {
	Categories []Category `json:"categories"`
}

// TODO if not dynamic scoring, sort after points?
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

	exClientResp, err := d.exClient.GetExerciseByTags(ctx, &proto.GetExerciseByTagsRequest{Tag: event.Config.ExerciseTags})
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

	sortCategories(categoriesFromExService.Categories)

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

	eventExercisesResponse := &EventExercisesResponse{
		Categories: []Category{},
	}

	// Populate each category with exercises
	for _, exServiceCategory := range categoriesFromExService.Categories {
		var exercises []Exercise
		for _, exServiceExercise := range exClientResp.Exercises {
			for _, instance := range exServiceExercise.Instance {
			Inner:
				for _, childExercise := range instance.Children {
					if childExercise.Category != exServiceCategory.Name {
						continue Inner
					}

					// Puts all solves for specific challenge into slice
					solves := []Solve{}
					for _, dbSolve := range solvesMap[childExercise.Tag] {
						solve := Solve{
							Date: dbSolve.Date.Format(time.RFC822),
							Team: dbSolve.Username,
						}
						solves = append(solves, solve)
					}

					// Is the challenge solved or not by the requesting team?
					solvedByTeam, ok := teamSolves[childExercise.Tag]
					if !ok {
						solvedByTeam = false
					}

					// Points are either from the config, or dynamic scoring
					var points int = int(childExercise.Points)
					if event.Config.DynamicScoring {
						if solvedByTeam {
							points = calculateScore(event.Config, float64(len(solvesMap[childExercise.Tag])-1))
						} else {
							points = calculateScore(event.Config, float64(len(solvesMap[childExercise.Tag])))
						}
					}

					// Since exercise description may hold markdown and pure html
					// Sanitize the exercise description
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
		// If no exercises were found for the category
		// Dont add the category to response
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

	teamSolves, err := d.db.GetTeamSolvesMap(ctx, dbTeam.ID)
	if err != nil {
		log.Error().Err(err).Msg("error getting team solves from database")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}

	// If the challenge to solve is static, lab is not required
	if exClientResp.Exercises[0].Static {
		log.Debug().Msg("static challenge found")
		for _, instance := range exClientResp.Exercises[0].Instance {
			for _, childExercise := range instance.Children {
				staticFlag := strings.Trim(childExercise.Static, " ")
				log.Debug().Str("exTag", childExercise.Tag).Str("flagFromLab", staticFlag).Str("flagFromRequest", req.Flag).Msg("comparing flags")
				if childExercise.Tag == req.Tag && staticFlag == strings.Trim(req.Flag, " ") {
					addSolveParams := db.AddSolveForTeamInEventParams{
						Tag:      req.Tag,
						Eventid:  dbEvent.ID,
						Teamid:   dbTeam.ID,
						Solvedat: time.Now().UTC(),
					}
					if err := d.db.AddSolveForTeamInEvent(ctx, addSolveParams); err != nil {
						log.Error().Err(err).Msg("error adding solve to database")
						c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
						return
					}
					sendCommandToTeam(team, updateChallenges)
					c.JSON(http.StatusOK, APIResponse{Status: "OK"})
					return
				}
			}
		}
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Unknown flag"})
		return
	}
	// If the challenge is a docker challenge
	// Lab is required for the most part to solve the challenge
	if team.Lab != nil {
		for _, exercise := range team.Lab.LabInfo.Exercises {
			for _, childExercise := range exercise.ChildExercises {
				if childExercise.Tag == req.Tag {
					flag := strings.Trim(childExercise.Flag, " ")
					log.Debug().Str("exTag", childExercise.Tag).Str("flagFromLab", flag).Str("flagFromRequest", req.Flag).Msg("comparing flags")
					if flag == strings.Trim(req.Flag, " ") {
						addSolveParams := db.AddSolveForTeamInEventParams{
							Tag:      req.Tag,
							Eventid:  dbEvent.ID,
							Teamid:   dbTeam.ID,
							Solvedat: time.Now().UTC(),
						}
						if err := d.db.AddSolveForTeamInEvent(ctx, addSolveParams); err != nil {
							log.Error().Err(err).Msg("error adding solve to database")
							c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
							return
						}
						sendCommandToTeam(team, updateChallenges)
						// Add the new solve to the solves map
						// And stop exercise if all children are solved
						teamSolves[req.Tag] = true
						if err := stopExerciseIfAllChildrenSolved(team, teamSolves, exClientResp.Exercises[0].Instance, req.ParentTag); err != nil {
							log.Error().Err(err).Msg("error stopping exercise after all challenges has been solved")
						}
						c.JSON(http.StatusOK, APIResponse{Status: "OK"})
						return
					} else {
						c.JSON(http.StatusBadRequest, APIResponse{Status: "Unknown flag"})
						return
					}
				}
			}
		}
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Start exercise to solve this challenge"})
		return
	}
	c.JSON(http.StatusBadRequest, APIResponse{Status: "Click \"Get a lab\" before solving this challenge"})
}

// Adds the exercise to the lab (creates and starts containers) or starts a stopped container
// Only a specific amount of exercises can be started at a time
// Will stop an specified exercise if more than 5 exercises are currently running
func (d *daemon) startExerciseInLab(c *gin.Context) {
	teamClaims := unpackTeamClaims(c)

	exerciseTag := c.Param("exerciseTag")
	exerciseToReplace := c.Query("replaces")

	if exerciseTag == exerciseToReplace {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "cannot replace exercise with itself"})
		return
	}

	event, err := d.eventpool.GetEvent(teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("could not find event in event pool")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "event for team is not currently running"})
		return
	}

	if !slices.Contains(event.Config.ExerciseTags, exerciseTag) {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "exercise not found in event"})
		return
	}

	if event.Config.Type == int32(TypeBeginner) {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "not usable in beginner lab"})
		return
	}

	team, err := event.GetTeam(teamClaims.Username)
	if err != nil {
		log.Error().Err(err).Msg("could not find team for event")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "could not find team for event"})
		return
	}

	if team.Status == RunningExerciseCommand {
		c.JSON(http.StatusTooManyRequests, APIResponse{Status: "too many requests", Message: "wait for existing request to finish"})
		return
	}
	team.M.Lock()
	log.Debug().Str("team", team.Username).Msg("Lock on team, eventExercises.go: 365")
	team.Status = RunningExerciseCommand
	defer func(team *Team) {
		team.Status = Idle
		team.M.Unlock()
		log.Debug().Str("team", team.Username).Msg("Unlock on team, eventExercises.go: 370")
		sendCommandToTeam(team, updateTeam)
	}(team)
	sendCommandToTeam(team, updateTeam)

	if team.Lab == nil {
		log.Debug().Str("team", team.Username).Msg("no lab configured for team")
		c.JSON(http.StatusNotFound, APIResponse{Status: "lab not found"})
		return
	}

	existsButStopped := false // Determines if we should run StartExerciseInLab or AddExercisesToLab
	replacementFound := false // Only used if there are more than 5 exercises running in a lab
	runningCount := 0

	// Get the running count, find replacement.
	// And And determine if challenge has already been added to the lab, but is just stopped.
	for _, exercise := range team.Lab.LabInfo.Exercises {
		running := false
		for _, machine := range exercise.Machines {
			if machine.Status == "running" {
				running = true
			}
		}
		if running {
			runningCount += 1
		}
		log.Debug().Str("exerciseToReplace", exerciseToReplace).Str("extag", exercise.Tag).Msg("exercise to replace and current exTag")
		if exerciseToReplace == exercise.Tag && running {
			replacementFound = true
		}
		if exercise.Tag == exerciseTag && running {
			c.JSON(http.StatusBadRequest, APIResponse{Status: "exercise already running in lab"})
			return
		} else if exercise.Tag == exerciseTag && !running {
			existsButStopped = true
		}
	}

	log.Debug().Int("runningCount", runningCount).Msg("exercises currently running in lab")

	if runningCount >= 5 && !replacementFound {
		c.JSON(http.StatusBadRequest, APIResponse{Status: "Limit on running challenges reached, stop another challenge before starting a new one"})
		return
	}

	if team.Lab.Conn != nil {
		ctx := context.Background()
		agentClient := aproto.NewAgentClient(team.Lab.Conn)

		// In case a replacement is needed, stop the exercise the new exercise replaces
		if replacementFound {
			agentReq := &aproto.ExerciseRequest{
				LabTag:   team.Lab.LabInfo.Tag,
				Exercise: exerciseToReplace,
			}
			if _, err := agentClient.StopExerciseInLab(ctx, agentReq); err != nil {
				log.Error().Err(err).Msg("error stopping exercise to replace")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
				return
			}
		}
		// If exercise is just stopped, just start it
		if existsButStopped {
			agentReq := &aproto.ExerciseRequest{
				LabTag:   team.Lab.LabInfo.Tag,
				Exercise: exerciseTag,
			}
			if _, err := agentClient.StartExerciseInLab(ctx, agentReq); err != nil {
				log.Error().Err(err).Msg("error starting exercise")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
				return
			}
			c.JSON(http.StatusOK, APIResponse{Status: "OK"})
			return
		}
		// If the exercise has not yet been added to the lab, add and start it
		exClientResp, err := d.exClient.GetExerciseByTags(ctx, &proto.GetExerciseByTagsRequest{Tag: []string{exerciseTag}})
		if err != nil {
			log.Error().Err(err).Msg("error getting exercise by tag from exDb")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
			return
		}
		// Unpack into exercise slice
		var exerConfs []*aproto.ExerciseConfig
		for _, e := range exClientResp.Exercises {
			ex, err := protobufToJson(e)
			if err != nil {
				log.Error().Err(err).Msg("error parsing protobuf to json")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
				return
			}
			estruct := &aproto.ExerciseConfig{}
			json.Unmarshal([]byte(ex), &estruct)
			exerConfs = append(exerConfs, estruct)
		}
		agentReq := &aproto.ExerciseRequest{
			LabTag:          team.Lab.LabInfo.Tag,
			ExerciseConfigs: exerConfs,
		}
		if _, err := agentClient.AddExercisesToLab(ctx, agentReq); err != nil {
			log.Error().Err(err).Msg("error adding exercise")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	log.Error().Msg("error starting exercise config: lab conn is nil")
	c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
}

// Will stop a requested exercise for a team
func (d *daemon) stopExercise(c *gin.Context) {
	teamClaims := unpackTeamClaims(c)

	exerciseTag := c.Param("exerciseTag")

	event, err := d.eventpool.GetEvent(teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("could not find event in event pool")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "event for team is not currently running"})
		return
	}

	team, err := event.GetTeam(teamClaims.Username)
	if err != nil {
		log.Error().Err(err).Msg("could not find team for event")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "could not find team for event"})
		return
	}

	if team.Status == RunningExerciseCommand {
		c.JSON(http.StatusTooManyRequests, APIResponse{Status: "too many requests", Message: "wait for existing request to finish"})
		return
	}
	team.M.Lock()
	log.Debug().Str("team", team.Username).Msg("Lock on team, eventExercises.go: 507")
	team.Status = RunningExerciseCommand
	defer func(team *Team) {
		team.Status = Idle
		team.M.Unlock()
		log.Debug().Str("team", team.Username).Msg("Unlock on team, eventExercises.go: 512")
		sendCommandToTeam(team, updateTeam)
	}(team)
	sendCommandToTeam(team, updateTeam)

	if team.Lab == nil {
		log.Debug().Str("team", team.Username).Msg("no lab configured for team")
		c.JSON(http.StatusNotFound, APIResponse{Status: "lab not found"})
		return
	}

	if team.Lab.Conn != nil {
		ctx := context.Background()
		agentClient := aproto.NewAgentClient(team.Lab.Conn)
		agentReq := &aproto.ExerciseRequest{
			LabTag:   team.Lab.LabInfo.Tag,
			Exercise: exerciseTag,
		}
		if _, err := agentClient.StopExerciseInLab(ctx, agentReq); err != nil {
			log.Error().Err(err).Msg("error stopping exercise")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	log.Error().Msg("error stopping exercise: lab conn is nil")
	c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
}

// Used by teams to reset specific exercise containers
func (d *daemon) resetExercise(c *gin.Context) {
	teamClaims := unpackTeamClaims(c)

	exerciseTag := c.Param("exerciseTag")

	event, err := d.eventpool.GetEvent(teamClaims.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("could not find event in event pool")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "event for team is not currently running"})
		return
	}

	team, err := event.GetTeam(teamClaims.Username)
	if err != nil {
		log.Error().Err(err).Msg("could not find team for event")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "could not find team for event"})
		return
	}

	if team.Status == RunningExerciseCommand {
		c.JSON(http.StatusTooManyRequests, APIResponse{Status: "too many requests", Message: "wait for existing request to finish"})
		return
	}
	team.M.Lock()
	log.Debug().Str("team", team.Username).Msg("Lock on team, eventExercises.go: 567")
	team.Status = RunningExerciseCommand
	defer func(team *Team) {
		team.Status = Idle
		team.M.Unlock()
		log.Debug().Str("team", team.Username).Msg("Unlock on team, eventExercises.go: 572")
		sendCommandToTeam(team, updateTeam)
	}(team)
	sendCommandToTeam(team, updateTeam)

	if team.Lab == nil {
		log.Debug().Str("team", team.Username).Msg("no lab configured for team")
		c.JSON(http.StatusNotFound, APIResponse{Status: "lab not found"})
		return
	}

	if event.Config.Type == int32(TypeAdvanced) {
		runningCount := 0
		chalToResetStatus := "stopped"
		for _, exercise := range team.Lab.LabInfo.Exercises {
			running := false
			for _, machine := range exercise.Machines {
				if machine.Status == "running" {
					running = true
				}
				if exerciseTag == exercise.Tag && machine.Status == "running" {
					chalToResetStatus = "running"
				}
			}
			if running {
				runningCount += 1
			}
		}
		log.Debug().Int("runningCount", runningCount).Msg("exercises currently running in lab")
		if runningCount >= 5 && chalToResetStatus == "stopped" {
			c.JSON(http.StatusBadRequest, APIResponse{Status: "Limit on running challenges reached, stop another challenge before resetting"})
			return
		}
	}

	if team.Lab.Conn != nil {
		ctx := context.Background()
		agentClient := aproto.NewAgentClient(team.Lab.Conn)
		agentReq := &aproto.ExerciseRequest{
			LabTag:   team.Lab.LabInfo.Tag,
			Exercise: exerciseTag,
		}
		if _, err := agentClient.ResetExerciseInLab(ctx, agentReq); err != nil {
			log.Error().Err(err).Msg("error resetting exercise")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	log.Error().Msg("error resetting exercise: lab conn is nil")
	c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
}

/*
	Stops a docker exercise if all children challenges for that

exercise has been solved
*/
func stopExerciseIfAllChildrenSolved(team *Team, teamSolvesMap map[string]bool, exerciseInstances []*proto.ExerciseInstance, parentTag string) error {
	// Run through all children exercises
	// Check if each child exercise exists in the solves map
	// If not just continue.
	for _, exerciseInstance := range exerciseInstances {
		for _, childExercise := range exerciseInstance.Children {
			log.Debug().Str("child tag", childExercise.Tag).Msg("checking if child is solved")
			if _, ok := teamSolvesMap[childExercise.Tag]; !ok {
				log.Debug().Msg("all children not solved... continueing without stopping exercise.")
				return nil
			}
		}
	}

	log.Debug().Msg("all children solved... stopping exercise")
	if team.Lab != nil {
		if team.Lab.Conn != nil {
			ctx := context.Background()
			agentClient := aproto.NewAgentClient(team.Lab.Conn)
			agentReq := &aproto.ExerciseRequest{
				LabTag:   team.Lab.LabInfo.Tag,
				Exercise: parentTag,
			}
			if _, err := agentClient.StopExerciseInLab(ctx, agentReq); err != nil {
				log.Error().Err(err).Msg("error stopping exercise")
				return err
			}
			sendCommandToTeam(team, updateTeam)
			return nil
		}
	}

	log.Error().Msg("error resetting exercise config: lab conn is nil")
	return errors.New("error error resetting exercise config: lab conn is nil")
}
