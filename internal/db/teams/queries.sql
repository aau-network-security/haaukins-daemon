-- name: AddTeam :exec
INSERT INTO teams (tag, event_id, email, name, password, created_at, last_access, solved_challenges) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: DeleteTeam :exec
DELETE FROM teams WHERE tag=$1 and event_id = $2;

-- name: UpdateTeamSolvedChl :exec
UPDATE teams SET solved_challenges = $2 WHERE tag = $1;

-- name: UpdateTeamPassword :exec
UPDATE teams SET password = $1 WHERE tag = $2 and event_id = $3;

-- name: TeamSolvedChls :many
SELECT solved_challenges FROM teams WHERE tag=$1;

-- name: GetTeamsForEvent :many
SELECT * FROM teams WHERE event_id=$1;

-- name: GetTeamCount :many
SELECT count(teams.id) FROM teams WHERE teams.event_id=$1;