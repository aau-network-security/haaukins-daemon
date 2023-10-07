package daemon

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/aau-network-security/haaukins-daemon/internal/db"
	"github.com/aau-network-security/haaukins-exercises/proto"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (d *daemon) adminExerciseSubrouter(r *gin.RouterGroup) {
	// Exercises
	exercises := r.Group("/exercises")

	exercises.Use(d.adminAuthMiddleware())
	exercises.GET("", d.getExercises)
	exercises.POST("/getbytags", d.getExercisesByTags)
	exercises.GET("/:category", d.getExercises)
	exercises.GET("/categories", d.getExerciseCategories)

	// Exercise profiles
	profiles := exercises.Group("/profiles")

	profiles.POST("", d.addProfile)
	profiles.GET("", d.getProfiles)
	profiles.PUT("/:profileId", d.updateProfile)
	profiles.DELETE("/:profilename", d.deleteProfile)
}

// returns a list of exercises from the exercise service where the organizer descriptions and challenge descriptions has been sanitized
func (d *daemon) getExercises(c *gin.Context) {
	ctx := context.Background()

	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is trying get all exercises")

	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, fmt.Sprintf("exercises::%s", admin.Organization), "read"},
		{admin.Username, admin.Organization, fmt.Sprintf("secretchals::%s", admin.Organization), "read"},
	}
	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[0] || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing listing exercises")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}
		category := c.Param("category")
		var exClientResp *proto.GetExercisesResponse
		if category == "" {
			exClientResp, err = d.exClient.GetExercises(ctx, &proto.Empty{})
			if err != nil {
				log.Error().Err(err).Msg("error while retrieving exercises from exercise service")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
				return
			}
		} else {
			exClientResp, err = d.exClient.GetExerciseByCategory(ctx, &proto.GetExerciseByCategoryRequest{Category: category})
			if err != nil {
				log.Error().Err(err).Msg("error while retrieving exercises from exercise service")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
				return
			}
		}

		var exercises []*proto.Exercise
		for _, exercise := range exClientResp.Exercises {
			if exercise.Secret && !authorized[1] {
				continue
			}

			// Sanitice team descriptions
			for _, instance := range exercise.Instance {
				for _, childExercise := range instance.Children {
					html, err := sanitizeUnsafeMarkdown([]byte(childExercise.TeamDescription))
					if err != nil {
						log.Error().Msgf("Error converting to commonmark: %s", err)
					}
					childExercise.TeamDescription = string(html)
				}
			}

			// Sanitize organizer description
			html, err := sanitizeUnsafeMarkdown([]byte(exercise.OrganizerDescription))
			if err != nil {
				log.Error().Msgf("Error converting to commonmark: %s", err)
			}

			exercise.OrganizerDescription = string(html)
			exercises = append(exercises, exercise)
		}

		sortExercises(exercises)

		c.JSON(http.StatusOK, APIResponse{Status: "OK", Exercises: exercises})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

func (d *daemon) getExercisesByTags(c *gin.Context) {
	ctx := context.Background()
	type GetExercisesByTagsRequest struct {
		Tags []string `json:"tags"`
	}

	var req GetExercisesByTagsRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error parsing request"})
		return
	}

	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is trying get all exercises")

	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, fmt.Sprintf("exercises::%s", admin.Organization), "read"},
		{admin.Username, admin.Organization, fmt.Sprintf("secretchals::%s", admin.Organization), "read"},
	}
	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[0] || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing listing exercises")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		req.Tags = removeDuplicates(req.Tags)
		exClientReq := &proto.GetExerciseByTagsRequest{
			Tag: req.Tags,
		}
		exClientResp, err := d.exClient.GetExerciseByTags(ctx, exClientReq)
		if err != nil {
			log.Error().Err(err).Msg("error while retrieving exercises from exercise service")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		var exercises []*proto.Exercise
		for _, exercise := range exClientResp.Exercises {
			if exercise.Secret && !authorized[1] {
				c.JSON(http.StatusForbidden, APIResponse{Status: "Access Denied"})
				return
			}

			// Sanitice team descriptions
			for _, instance := range exercise.Instance {
				for _, childExercise := range instance.Children {
					html, err := sanitizeUnsafeMarkdown([]byte(childExercise.TeamDescription))
					if err != nil {
						log.Error().Msgf("Error converting to commonmark: %s", err)
					}
					childExercise.TeamDescription = string(html)
				}
			}

			// Sanitize organizer description
			html, err := sanitizeUnsafeMarkdown([]byte(exercise.OrganizerDescription))
			if err != nil {
				log.Error().Msgf("Error converting to commonmark: %s", err)
			}

			exercise.OrganizerDescription = string(html)
			exercises = append(exercises, exercise)
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK", Exercises: exercises})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// Returns a list of all categories and their sanitized descriptions from the exercise service
func (d *daemon) getExerciseCategories(c *gin.Context) {
	ctx := context.Background()

	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is trying get all categories")

	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, fmt.Sprintf("exercises::%s", admin.Organization), "read"},
	}
	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[0] || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing listing categories")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		exClientResp, err := d.exClient.GetCategories(ctx, &proto.Empty{})
		if err != nil {
			log.Error().Err(err).Msg("error while retrieving list of categories from exercise service")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		for _, category := range exClientResp.Categories {
			// Sanitize category description
			html, err := sanitizeUnsafeMarkdown([]byte(category.CatDesc))
			if err != nil {
				log.Error().Msgf("Error converting to commonmark: %s", err)
			}
			category.CatDesc = string(html)
		}

		sortCategories(exClientResp.Categories)

		c.JSON(http.StatusOK, APIResponse{Status: "OK", Categories: exClientResp.Categories})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

type ExerciseProfileRequest struct {
	Name         string   `json:"name" binding:"required"`
	ExerciseTags []string `json:"exerciseTags" binding:"required"`
	Description  string   `json:"description"`
	Public       bool     `json:"public"`
	Organization string   `json:"organization"`
}

// Adds a profile for the organization of the requesting admin to the database
func (d *daemon) addProfile(c *gin.Context) {
	ctx := context.Background()

	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is trying add a profile")

	var req ExerciseProfileRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error parsing request"})
		return
	}

	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, fmt.Sprintf("challengeProfiles::%s", admin.Organization), "write"},
		{admin.Username, admin.Organization, fmt.Sprintf("secretchals::%s", admin.Organization), "write"},
	}
	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[0] || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing event creation")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		req.ExerciseTags = removeDuplicates(req.ExerciseTags)

		exClientResp, err := d.exClient.GetExerciseByTags(ctx, &proto.GetExerciseByTagsRequest{Tag: req.ExerciseTags})
		if err != nil {
			log.Error().Err(err).Msg("error while retrieving exercises by tags")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		secret := false
		for _, exercise := range exClientResp.Exercises {
			if exercise.Secret && !authorized[1] {
				log.Warn().Msg("admin user without secret rights tried creating an event with secret challenges")
				c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
				return
			}

			if exercise.Secret {
				secret = true
			}
		}

		checkProfileParams := db.CheckIfProfileExistsParams{
			Profilename: req.Name,
			Orgname:     admin.Organization,
		}
		profileExists, err := d.db.CheckIfProfileExists(ctx, checkProfileParams)
		if err != nil {
			log.Error().Err(err).Msg("error checking if profile exists")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
			return
		}
		if profileExists {
			log.Debug().Msg("profile already exists")
			c.JSON(http.StatusBadRequest, APIResponse{Status: "profile already exists"})
			return
		}

		dbProfileParams := db.AddProfileParams{
			Profilename: req.Name,
			Secret:      secret,
			Orgname:     admin.Organization,
			Description: req.Description,
			Public:      req.Public,
		}
		profileId, err := d.db.AddProfile(ctx, dbProfileParams)
		if err != nil {
			log.Error().Err(err).Msg("error adding profile to db")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
			return
		}

		for _, exercise := range exClientResp.Exercises {
			dbProfileExercise := db.AddProfileChallengeParams{
				Tag:       exercise.Tag,
				Name:      exercise.Name,
				Profileid: profileId,
			}
			if err := d.db.AddProfileChallenge(ctx, dbProfileExercise); err != nil {
				log.Error().Err(err).Msg("error adding exercise to profile in database")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
				return
			}
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// Update profile is a full replacement of another profile in the same organization with the same name
func (d *daemon) updateProfile(c *gin.Context) {
	ctx := context.Background()

	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is trying add a profile")

	var req ExerciseProfileRequest
	if err := c.BindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Error parsing request data: ")
		c.JSON(http.StatusBadRequest, APIResponse{Status: "error parsing request"})
		return
	}

	profileId, err := strconv.ParseInt(c.Param("profileId"), 10, 32)
	if err != nil {
		log.Error().Err(err).Msg("error parsing profile ID")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}
	log.Debug().Int64("profileId", profileId).Msg("updating profile")

	oldProfile, err := d.db.GetProfileById(ctx, int32(profileId))
	if err != nil {
		if err == sql.ErrNoRows {
			log.Error().Int64("profileId", profileId).Msg("Profile not found")
			c.JSON(http.StatusNotFound, APIResponse{Status: "profile not found"})
			return
		}
		log.Error().Err(err).Msgf("Error getting old profile from db")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
		return
	}

	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, fmt.Sprintf("challengeProfiles::%s", admin.Organization), "write"},
		{admin.Username, admin.Organization, fmt.Sprintf("secretchals::%s", admin.Organization), "write"},
		{admin.Username, admin.Organization, "objects::Admins", "write"},
	}
	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[0] || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing event creation")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		req.ExerciseTags = removeDuplicates(req.ExerciseTags)

		exClientResp, err := d.exClient.GetExerciseByTags(ctx, &proto.GetExerciseByTagsRequest{Tag: req.ExerciseTags})
		if err != nil {
			log.Error().Err(err).Msg("error while retrieving exercises by tags")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		if oldProfile.Organization != admin.Organization && !authorized[2] {
			c.JSON(http.StatusForbidden, APIResponse{Status: "Access denied"})
			return
		}

		// A superadmin can edit profiles in all organizations
		organization := oldProfile.Organization
		if req.Organization != "" && authorized[2] {
			organization = req.Organization
		} else if req.Organization != "" && !authorized[2] {
			c.JSON(http.StatusForbidden, APIResponse{Status: "Access denied"})
			return
		}

		secret := false
		for _, exercise := range exClientResp.Exercises {
			if exercise.Secret && !authorized[1] {
				log.Warn().Msg("admin user without secret rights tried creating an event with secret challenges")
				c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
				return
			}

			if exercise.Secret {
				secret = true
			}
		}

		tx, err := d.dbConn.Begin()
		if err != nil {
			log.Error().Err(err).Msg("error beginning db transaction")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
			return
		}
		defer tx.Rollback()

		qtx := d.db.WithTx(tx)

		// Update the profile info
		dbProfileParams := db.UpdateProfileParams{
			ID:          int32(profileId),
			Profilename: req.Name,
			Secret:      secret,
			Orgname:     organization,
			Description: req.Description,
			Public:      req.Public,
		}
		if err := qtx.UpdateProfile(ctx, dbProfileParams); err != nil {
			log.Error().Err(err).Msg("error updating profile")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
			return
		}

		// Update the profile challenges
		if err := qtx.DeleteProfileChallenges(ctx, int32(profileId)); err != nil {
			log.Error().Err(err).Msg("error deleting profile challenges")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
			return
		}

		for _, exercise := range exClientResp.Exercises {
			dbProfileExercise := db.AddProfileChallengeParams{
				Tag:       exercise.Tag,
				Name:      exercise.Name,
				Profileid: int32(profileId),
			}
						if err := qtx.AddProfileChallenge(ctx, dbProfileExercise); err != nil {
				log.Error().Err(err).Msg("error adding exercise to profile in database")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
				return
			}
		}
		if err := tx.Commit(); err != nil {
			log.Error().Err(err).Msg("error committing transaction")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
			return
		}
		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// Delete a profile by name from the requesters organization
func (d *daemon) deleteProfile(c *gin.Context) {
	ctx := context.Background()

	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is trying delete a profile")

	profileName := c.Param("profilename")

	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, fmt.Sprintf("challengeProfiles::%s", admin.Organization), "write"},
		{admin.Username, admin.Organization, fmt.Sprintf("secretchals::%s", admin.Organization), "write"},
	}
	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[0] || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing event creation")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		getProfileParams := db.GetProfileByNameAndOrgNameParams{
			Profilename: profileName,
			Orgname:     admin.Organization,
		}
		profile, err := d.db.GetProfileByNameAndOrgName(ctx, getProfileParams)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Debug().Msg("profile not found")
				c.JSON(http.StatusBadRequest, APIResponse{Status: "profile not found"})
				return
			}
			log.Error().Err(err).Msg("error getting profile from database")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
			return
		}

		if profile.Secret && !authorized[1] {
			log.Warn().Str("admin", admin.Username).Msg("admin tried to delete a secret profile without having rights to do so")
			c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
			return
		}

		deleteProfileParams := db.DeleteProfileParams{
			Profilename: profileName,
			Orgname:     admin.Organization,
		}
		if err := d.db.DeleteProfile(ctx, deleteProfileParams); err != nil {
			log.Error().Err(err).Msg("error deleting profile")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
			return
		}

		c.JSON(http.StatusOK, APIResponse{Status: "OK"})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// Lists all profile for the requesters organization
func (d *daemon) getProfiles(c *gin.Context) {
	ctx := context.Background()

	admin, err := d.getUserFromGinContext(c)
	if err != nil {
		log.Error().Err(err).Msg("error getting user from gin context")
		c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal Server Error"})
		return
	}
	d.auditLogger.Info().
		Time("UTC", time.Now().UTC()).
		Str("AdminUser", admin.Username).
		Str("AdminEmail", admin.Email).
		Msg("AdminUser is trying list profiles")

	var casbinRequests = [][]interface{}{
		{admin.Username, admin.Organization, fmt.Sprintf("challengeProfiles::%s", admin.Organization), "read"},
		{admin.Username, admin.Organization, fmt.Sprintf("secretchals::%s", admin.Organization), "read"},
	}
	if authorized, err := d.enforcer.BatchEnforce(casbinRequests); authorized[0] || err != nil {
		if err != nil {
			log.Error().Err(err).Msgf("Encountered an error while authorizing event creation")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		if authorized[1] {
			publicProfiles, err := d.db.GetAllPublicProfiles(ctx)
			if err != nil {
				log.Error().Err(err).Msg("error getting all public profiles")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
				return
			}
			orgProfiles, err := d.db.GetAllProfilesInOrg(ctx, admin.Organization)
			if err != nil {
				log.Error().Err(err).Msg("error getting all profiles in organization")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
				return
			}

			profiles := append(orgProfiles, publicProfiles...)

			profilesToReturn, err := d.populateProfiles(ctx, profiles, admin)
			if err != nil {
				log.Error().Err(err).Msg("error populating profiles with exercises")
				c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
				return
			}

			c.JSON(http.StatusOK, APIResponse{Status: "OK", Profiles: profilesToReturn})
			return
		}

		publicProfiles, err := d.db.GetNonSecretPublicProfiles(ctx)
		if err != nil {
			log.Error().Err(err).Msg("error getting all non secret public profiles")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		orgProfiles, err := d.db.GetNonSecretProfilesInOrg(ctx, admin.Organization)
		if err != nil {
			log.Error().Err(err).Msg("error getting non secret profiles in organization")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		profiles := append(orgProfiles, publicProfiles...)

		profilesToReturn, err := d.populateProfiles(ctx, profiles, admin)
		if err != nil {
			log.Error().Err(err).Msg("error populating profiles with exercises")
			c.JSON(http.StatusInternalServerError, APIResponse{Status: "Internal server error"})
			return
		}

		c.JSON(http.StatusOK, APIResponse{Status: "OK", Profiles: profilesToReturn})
		return
	}
	c.JSON(http.StatusUnauthorized, APIResponse{Status: "Unauthorized"})
}

// Calls the sql query to inner join exercises for each profile and returns a populated list of profiles
func (d *daemon) populateProfiles(ctx context.Context, profiles []db.Profile, admin AdminClaims) ([]ExerciseProfile, error) {
	var profilesToReturn []ExerciseProfile
	for _, profile := range profiles {
		getProfileExercisesParams := db.GetExercisesInProfileParams{
			Profileid: profile.ID,
			Orgname:   admin.Organization,
		}
		exercises, err := d.db.GetExercisesInProfile(ctx, getProfileExercisesParams)
		if err != nil {
			return nil, err
		}
		profileToReturn := ExerciseProfile{
			Id:           profile.ID,
			Name:         profile.Name,
			Organization: profile.Organization,
			Public:       profile.Public,
			Description:  profile.Description,
			Secret:       profile.Secret,
			Exercises:    exercises,
		}
		profilesToReturn = append(profilesToReturn, profileToReturn)
	}
	return profilesToReturn, nil
}
