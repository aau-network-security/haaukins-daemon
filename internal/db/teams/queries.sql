-- name: AddTeam :exec
INSERT INTO teams (tag, event_id, email, username, password, created_at, last_access) VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: CheckIfTeamExistsForEvent :one
SELECT EXISTS( SELECT 1 FROM teams WHERE lower(username) = lower(@username) AND event_id = @eventId);

-- name: GetTeamFromEventByUsername :one
SELECT * FROM teams WHERE lower(username) = lower(@username) AND event_id = @eventId;

-- name: GetTeamFromEventByUsernameNoPw :one
SELECT (username, email) FROM teams WHERE lower(username) = lower(@username) AND event_id = @eventId;

-- name: DeleteTeam :exec
DELETE FROM teams WHERE tag=$1 and event_id = $2;

-- name: UpdateTeamPassword :exec
UPDATE teams SET password = $1 WHERE tag = $2 and event_id = $3;

-- name: GetTeamsForEvent :many
SELECT * FROM teams WHERE event_id=$1;

-- name: GetTeamCount :one
SELECT count(teams.id) FROM teams WHERE teams.event_id=$1;
