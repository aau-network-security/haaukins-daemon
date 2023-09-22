package daemon

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
	"github.com/aau-network-security/haaukins-daemon/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (d *daemon) adminEventTeamsSubrouter(r *gin.RouterGroup) {
	teams := r.Group("/teams")

	teams.Use(d.adminAuthMiddleware())
	// CRUD

	teams.GET("/:eventTag", d.getTeams)
	teams.DELETE("/:teamname", d.deleteTeam)

	// Additional routes
	teams.PUT("", d.updateTeam)
	teams.POST("/solve", d.forceSolveExercise)
}

func (d *daemon) getTeams(c *gin.Context) {
	type ChildExerciseResp struct {
		Name   string `json:"name"`
		Tag    string `json:"tag"`
		Flag   string `json:"flag"`
		Solved bool   `json:"solved"`
	}

	type ExerciseResp struct {
		Tag            string              `json:"tag"`
		Machines       []*aproto.Machine   `json:"machines"`
		ChildExercises []ChildExerciseResp `json:"childExercises"`
	}

	type LabInfoResp struct {
		Tag       string         `json:"tag"`
		Exercises []ExerciseResp `json:"exercises"`
	}

	type GetTeamsResponse struct {
		Tag        string      `json:"tag"`
		Email      string      `json:"email"`
		Username   string      `json:"username"`
		Status     string      `json:"status"`
		CreatedAt  time.Time   `json:"createdAt"`
		LastAccess time.Time   `json:"lastAccess"`
		LabInfo    LabInfoResp `json:"labInfo"`
	}

	ctx := context.Background()

	eventTag := c.Param("eventTag")

	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("EventTag", eventTag).
		Msg("AdminUser is trying to get teams for event")

	dbEvent, err := d.db.GetEventByTag(ctx, eventTag)
	if err != nil {
		log.Error().Err(err).Msg("error getting event from event pool")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}

	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, "events::Admins", "read"},
		{admin.Username, admin.Organization, fmt.Sprintf("events::%s", dbEvent.Organization), "read"},
		{admin.Username, admin.Organization, fmt.Sprintf("notOwnedEvents::%s", dbEvent.Organization), "read"},
	}

	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[0] || authorized[1] || err != nil {
		if !authorized[2] {
			if dbEvent.Createdby != admin.Username {
				c.JSON(http.StatusForbidden, gin.H{"status": "Forbidden"})
				return
			}
		}

		event, _ := d.eventpool.GetEvent(eventTag) // Only to get team status

		dbTeams, err := d.db.GetTeamsForEvent(ctx, dbEvent.ID)
		if err != nil {
			log.Error().Err(err).Msg("error getting teams for event")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
			return
		}

		teams := []GetTeamsResponse{}
		for _, dbTeam := range dbTeams {
			teamStatus := "N/A"
			labInfo := LabInfoResp{}
			var poolTeam *Team
			if event != nil {
				poolTeam, _ = event.GetTeam(dbTeam.Username)
			}
			if poolTeam != nil {
				eventConfig := event.GetConfig()
				solves, err := d.db.GetEventSolvesMap(ctx, event.DbId)
				if err != nil {
					log.Error().Err(err).Str("eventTag", event.Config.Tag).Msg("error getting solves for event")
					c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
					return
				}
				poolTeam.LockForFunc(func() {
					teamStatus = poolTeam.Status.String()
					if poolTeam.Lab != nil {
						labInfo.Tag = poolTeam.Lab.LabInfo.Tag
						exercisesResp := []ExerciseResp{}
						for _, exConfig := range eventConfig.ExerciseConfigs {
							exerciseResp := ExerciseResp{
								Tag:            exConfig.Tag,
								Machines:       []*aproto.Machine{},
								ChildExercises: []ChildExerciseResp{},
							}
							for _, exercise := range poolTeam.Lab.LabInfo.Exercises {
								if exercise.Tag == exConfig.Tag {
									exerciseResp.Machines = exercise.Machines
								}
							}
							for _, instance := range exConfig.Instance {
								for _, child := range instance.Children {
									childExerciseResp := ChildExerciseResp{
										Name:   child.Name,
										Tag:    child.Tag,
										Flag:   "Challenge has not yet been started",
										Solved: false,
									}
									for _, solve := range solves[child.Tag] {
										if solve.Username == poolTeam.Username {
											childExerciseResp.Solved = true
										}
									}
									if child.Static != "" {
										childExerciseResp.Flag = child.Static
									} else {
										for _, exercise := range poolTeam.Lab.LabInfo.Exercises {
											for _, childExercise := range exercise.ChildExercises {
												if childExercise.Tag == child.Tag {
													childExerciseResp.Flag = childExercise.Flag
												}
											}
										}
									}
									exerciseResp.ChildExercises = append(exerciseResp.ChildExercises, childExerciseResp)
								}
							}
							exercisesResp = append(exercisesResp, exerciseResp)
						}
						labInfo.Exercises = exercisesResp
					}
				})
			}

			team := GetTeamsResponse{
				Tag:        dbTeam.Tag,
				Email:      dbTeam.Email,
				Username:   dbTeam.Username,
				Status:     teamStatus,
				CreatedAt:  dbTeam.CreatedAt,
				LastAccess: dbTeam.LastAccess.Time,
				LabInfo:    labInfo,
			}
			teams = append(teams, team)
		}
		c.JSON(http.StatusOK, gin.H{
			"status": "OK",
			"teams":  teams,
		})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) deleteTeam(c *gin.Context) {

}

func (d *daemon) updateTeam(c *gin.Context) {

}

func (d *daemon) forceSolveExercise(c *gin.Context) {
	type ForceSolveParams struct {
		EventTag    string `json:"eventTag"`
		ExerciseTag string `json:"exerciseTag"`
		TeamName    string `json:"teamName"`
	}

	var req ForceSolveParams
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error parsing request"})
		return
	}

	admin := unpackAdminClaims(c)
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Str("EventTag", req.EventTag).
		Msg("AdminUser is trying to get teams for event")

	dbEvent, err := d.db.GetEventByTag(c, req.EventTag)
	if err != nil {
		log.Error().Err(err).Msg("error getting event from event pool")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}

	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, "events::Admins", "write"},
		{admin.Username, admin.Organization, fmt.Sprintf("events::%s", dbEvent.Organization), "write"},
		{admin.Username, admin.Organization, fmt.Sprintf("notOwnedEvents::%s", dbEvent.Organization), "write"},
	}

	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[0] || authorized[1] || err != nil {
		if !authorized[2] {
			if dbEvent.Createdby != admin.Username {
				c.JSON(http.StatusForbidden, gin.H{"status": "Forbidden"})
				return
			}
		}
		team, err := d.db.GetTeamFromEventByUsername(c, db.GetTeamFromEventByUsernameParams{
			Username: req.TeamName,
			Eventid:  dbEvent.ID,
		})
		if err != nil {
			log.Error().Err(err).Str("event", dbEvent.Tag).Msg("error getting team for event from db")
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"status": "Team not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Internal server error"})
			return
		}

		teamSolves, err := d.db.GetTeamSolvesMap(c, team.ID)
		if _, ok := teamSolves[req.ExerciseTag]; ok {
			c.JSON(http.StatusBadRequest, gin.H{"status": "Bad request, already solved"})
			return
		}

		event, err := d.eventpool.GetEvent(req.EventTag)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Internal server error"})
			return
		}

		eventConfig := event.GetConfig()
		exerciseExists := false
	Outer:
		for _, exerciseConfig := range eventConfig.ExerciseConfigs {
			for _, instance := range exerciseConfig.Instance {
				for _, child := range instance.Children {
					if child.Tag == req.ExerciseTag {
						exerciseExists = true
						break Outer
					}
				}
			}
		}
		if !exerciseExists {
			c.JSON(http.StatusBadRequest, gin.H{"status": "Bad request, exercise does not exist in event"})
		}

		addSolveParams := db.AddSolveForTeamInEventParams{
			Tag:      req.ExerciseTag,
			Eventid:  dbEvent.ID,
			Teamid:   team.ID,
			Solvedat: time.Now(),
		}
		if err := d.db.AddSolveForTeamInEvent(c, addSolveParams); err != nil {
			log.Error().Err(err).Msg("error adding forced solve")
			c.JSON(http.StatusInternalServerError, gin.H{"status": "Internal server error"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}
