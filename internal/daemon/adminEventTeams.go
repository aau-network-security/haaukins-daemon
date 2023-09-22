package daemon

import (
	"context"
	"fmt"
	"net/http"
	"time"

	aproto "github.com/aau-network-security/haaukins-agent/pkg/proto"
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
}

func (d *daemon) getTeams(c *gin.Context) {
	type ChildExerciseResp struct {
		Name string `json:"name"`
		Tag  string `json:"tag"`
		Flag string `json:"flag"`
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
		eventConfig := event.GetConfig()

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
				poolTeam.LockForFunc(func() {
					teamStatus = poolTeam.Status.String()
					labInfo.Tag = poolTeam.Lab.LabInfo.Tag
					if poolTeam.Lab != nil {
						exercisesResp := []ExerciseResp{}
						for _, exercise := range poolTeam.Lab.LabInfo.Exercises {
							for _, exConfig := range eventConfig.ExerciseConfigs {
								if exercise.Tag == exConfig.Tag {
									childExercisesResp := []ChildExerciseResp{}
									for _, childExercise := range exercise.ChildExercises {
										log.Debug().Str("ChildExercise", childExercise.Tag).Msg("Trying to assemble children")
										for _, instance := range exConfig.Instance {
											for _, childExConfig := range instance.Children {
												if childExercise.Tag == childExConfig.Tag {
													childExerciseResp := ChildExerciseResp{
														Name: childExConfig.Name,
														Tag:  childExConfig.Tag,
														Flag: childExercise.Flag,
													}
													childExercisesResp = append(childExercisesResp, childExerciseResp)
												}
											}
										}
									}
									exerciseResp := ExerciseResp{
										Tag:            exercise.Tag,
										Machines:       exercise.Machines,
										ChildExercises: childExercisesResp,
									}
									exercisesResp = append(exercisesResp, exerciseResp)
								}
							}
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
