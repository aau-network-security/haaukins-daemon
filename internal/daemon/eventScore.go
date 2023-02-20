package daemon

import (
	"context"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (d *daemon) eventScoreSubrouter(r *gin.RouterGroup) {
	team := r.Group("/scores")

	team.GET("/:eventTag", d.getScores)
}

type ScoreResponse struct {
	ChallengesList []struct {
		Name string `json:"name"`
		Tag  string `json:"tag"`
	} `json:"challengesList"`
	TeamsScores []TeamScore `json:"teamsScore"`
}

type TeamScore struct {
	Rank              int                  `json:"rank"`
	TeamName          string               `json:"teamName"`
	Score             int                  `json:"score"`
	TeamSolves        map[string]TeamSolve `json:"solves"`
	LatestSolve       time.Time            `json:"latestSolve"`
	TeamScoreTimeline [][]interface{}      `json:"teamScoreTimeline"`
}

type TeamSolve struct {
	Tag    string `json:"tag"`
	Solved bool   `json:"solved"`
	Rank   int    `json:"rank"`
}

type solveForTimeline struct {
	date   time.Time
	points int
}

// TODO add comments
func (d *daemon) getScores(c *gin.Context) {
	ctx := context.Background()
	//teamClaims := unpackTeamClaims(c)
	eventTag := c.Param("eventTag")

	event, err := d.eventpool.GetEvent(eventTag)
	if err != nil {
		log.Error().Err(err).Msg("could not find event in event pool")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "event for team is not currently running"})
		return
	}

	exClientReq := &proto.GetExerciseByTagsRequest{
		Tag: event.Config.ExerciseTags,
	}
	exClientResp, err := d.exClient.GetExerciseByTags(ctx, exClientReq)
	if err != nil {
		log.Error().Err(err).Msg("error getting exercises by tags")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}

	var challengesList []struct {
		Name string `json:"name"`
		Tag  string `json:"tag"`
	}
	for _, exercise := range exClientResp.Exercises {
		for _, instance := range exercise.Instance {
			for _, child := range instance.Children {
				challengesList = append(challengesList, struct {
					Name string `json:"name"`
					Tag  string `json:"tag"`
				}{
					Name: child.Name,
					Tag:  child.Tag,
				})
			}
		}
	}

	// Assembling a map of points in case event is not uising dynamic scoring
	exPointMap := make(map[string]int32)
	if !event.Config.DynamicScoring {
		for _, exercise := range exClientResp.Exercises {
			for _, instance := range exercise.Instance {
				for _, child := range instance.Children {
					exPointMap[child.Tag] = child.Points
				}
			}
		}
	}

	eventDbTeams, err := d.db.GetTeamsForEvent(ctx, event.DbId)
	if err != nil {
		log.Error().Err(err).Msg("error getting teams for event")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}

	solvesMap, err := d.db.GetEventSolvesMap(ctx, event.DbId)
	if err != nil {
		log.Error().Err(err).Msg("error getting solves map for event from database")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "internal server error"})
		return
	}

	var teamScores []TeamScore
	for _, team := range eventDbTeams {
		teamSolves := make(map[string]TeamSolve)

		solvesForTimeline := []solveForTimeline{}
		var teamScoreTimeline [][]interface{}
		score := 0
	OuterExLoop:
		for exTag, solves := range solvesMap {
			exSolveCount := len(solves)
			for index, solve := range solves {
				if team.Username == solve.Username {
					teamSolves[exTag] = TeamSolve{
						Tag:    exTag,
						Solved: true,
						Rank:   index + 1,
					}
					points := 0
					if event.Config.DynamicScoring {
						points = calculateScore(event.Config, float64(exSolveCount-1)) // deducting one since score algorithm shows current score
						score += points
					} else {
						points = int(exPointMap[exTag])
						score += points
					}
					solvesForTimeline = append(solvesForTimeline, solveForTimeline{
						date:   solve.Date,
						points: points,
					})
					continue OuterExLoop
				}
			}
		}

		sortTimeline(solvesForTimeline)
		scoreForTimeline := 0
		var teamScoreTime []interface{}
		teamScoreTime = append(teamScoreTime, event.StartedAt)
		teamScoreTime = append(teamScoreTime, 0)
		teamScoreTimeline = append(teamScoreTimeline, teamScoreTime)
		for _, solveForTimeLine := range solvesForTimeline {
			teamScoreTime = []interface{}{}
			teamScoreTime = append(teamScoreTime, solveForTimeLine.date)
			scoreForTimeline += solveForTimeLine.points
			teamScoreTime = append(teamScoreTime, scoreForTimeline)
			teamScoreTimeline = append(teamScoreTimeline, teamScoreTime)
		}

		latestSolve := teamScoreTimeline[len(teamScoreTimeline)-1][0].(time.Time)
		teamScores = append(teamScores, TeamScore{
			TeamName:          team.Username,
			Score:             score,
			TeamSolves:        teamSolves,
			LatestSolve:       latestSolve,
			TeamScoreTimeline: teamScoreTimeline,
		})

	}

	sortTeamScores(teamScores)

	//Inserting their rank
	for i := range teamScores {
		teamScores[i].Rank = i + 1
	}

	ScoreResponse := ScoreResponse{
		ChallengesList: challengesList,
		TeamsScores:    teamScores,
	}
	// c.JSON(http.StatusOK, APIResponse{Status: "OK"})
	c.JSON(http.StatusOK, ScoreResponse)
}

func sortTeamScores(teamsScore []TeamScore) {
	sort.SliceStable(teamsScore, func(p, q int) bool {
		return teamsScore[p].Score > teamsScore[q].Score
	})

	sort.SliceStable(teamsScore, func(p, q int) bool {
		if teamsScore[p].Score == teamsScore[q].Score {
			return teamsScore[p].LatestSolve.Before(teamsScore[q].LatestSolve)
		}
		return false
	})
}

func sortTimeline(solvesForTimeline []solveForTimeline) {
	sort.SliceStable(solvesForTimeline, func(p, q int) bool {
		return solvesForTimeline[p].date.Before(solvesForTimeline[q].date)
	})
}

// Implementing dynamic scoring function https://github.com/sigpwny/ctfd-dynamic-challenges-mod/blob/main/__init__.py
const (
	p0 = 0.7
	p1 = 0.96
)

var (
	c0 = -math.Atanh(p0)
	c1 = math.Atanh(p1)
)

func dynA(solves float64) float64 {
	return (1 - math.Tanh(solves)) / 2
}

func dynB(solves float64) float64 {
	return (dynA((c1-c0)*solves+c0) - dynA(c1)) / (dynA(c0) - dynA(c1))
}

// Returns the dynamic score of an exercise based on the amount of solves.
//
// To get the score of the exercise for the next solve, you just pass the direct amount of solves.
//
// To get a current teams score you need to take the amount of solves for the exercise
// and substract 1
func calculateScore(eventConf EventConfig, solves float64) int {
	solves = math.Max(0, solves)
	s := math.Max(1, float64(eventConf.DynamicSolveThreshold))
	f := func(solves float64) float64 {
		return float64(eventConf.DynamicMin) + (float64(eventConf.DynamicMax)-float64(eventConf.DynamicMin))*dynB(solves/s)
	}
	return int(math.Round(math.Max(f(float64(solves)), f(s))))
}

// ctx := context.Background()
// eventConf := EventConfig{
// 	DynamicMax:            2000,
// 	DynamicMin:            50,
// 	DynamicSolveThreshold: 200,
// }
// c.JSON(http.StatusOK, calculateScore(eventConf, 50))
// res, err := d.db.GetEventSolvesMap(ctx, 4)
// if err != nil {
// 	log.Error().Err(err).Msg("error getting solves for event")
// }
// c.JSON(http.StatusOK, res)
