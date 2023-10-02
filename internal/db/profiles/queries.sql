-- name: AddProfile :one
INSERT INTO profiles (name, secret, organization, description, public) VALUES (@profileName, @secret, @orgName, @description, @public) RETURNING id;

-- name: AddProfileChallenge :exec
INSERT INTO profile_challenges (tag, name, profile_id) VALUES (@tag, @name, @profileId);

-- name: GetProfiles :many
SELECT * FROM profiles;

-- name: GetAllPublicProfiles :many
SELECT * FROM profiles WHERE public = TRUE;

-- name: GetNonSecretPublicProfiles :many
SELECT * FROM profiles WHERE secret = FALSE AND public = TRUE;

-- name: GetAllProfilesInOrg :many
SELECT * FROM profiles WHERE lower(organization) = lower(@orgName) AND public = FALSE;

-- name: GetNonSecretProfilesInOrg :many
SELECT * FROM profiles WHERE lower(organization) = lower(@orgName) and secret = FALSE AND public = FALSE;

-- name: GetProfileByNameAndOrgName :one
SELECT * FROM profiles WHERE lower(name) = lower(@profileName) AND lower(organization) = lower(@orgName);

-- name: GetExercisesInProfile :many
SELECT profile_challenges.id, profile_challenges.tag, profile_challenges.name  FROM profiles INNER JOIN profile_challenges ON profiles.id = profile_challenges.profile_id WHERE profiles.id = @profileId AND profiles.organization = @orgName ORDER BY profiles.id asc;

-- name: DeleteProfile :exec
DELETE FROM profiles WHERE lower(name) = lower(@profileName) AND lower(organization) = lower(@orgName);

-- name: CheckIfProfileExists :one
SELECT EXISTS(SELECT 1 FROM profiles WHERE lower(name) = lower(@profileName) AND lower(organization) = lower(@orgName));