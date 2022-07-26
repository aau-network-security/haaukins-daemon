-- name: AddProfile :exec
INSERT INTO profiles (name, secret, challenges) VALUES ($1, $2, $3);

-- name: GetProfiles :many
SELECT * FROM profiles ORDER BY id asc;

-- name: UpdateProfile :exec
UPDATE profiles SET secret = $1, challenges = $2 WHERE name = $3;

-- name: DeleteProfile :exec
DELETE FROM profiles WHERE name = $1;

-- name: CheckProfileExists :one
SELECT EXISTS(SELECT 1 FROM profiles WHERE name = $1);

-- name: AddTeam :exec
INSERT INTO team (tag, event_id, email, name, password, created_at, last_access, solved_challenges) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: DeleteTeam :exec
DELETE FROM team WHERE tag=$1 and event_id = $2;

-- name: AddEvent :exec
INSERT INTO event (tag, name, available, capacity, frontends, status, exercises, started_at, finish_expected, finished_at, createdby, onlyvpn,secretKey, disabledExercises) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,$11,$12,$13,$14);

-- name: UpdateCloseEvent :exec
UPDATE event SET tag = $2, finished_at = $3 WHERE tag = $1;

-- name: UpdateEventStatus :exec
UPDATE event SET status = $2 WHERE tag = $1;

-- name: UpdateExercises :exec
-- UPDATE event SET exercises = (SELECT (SELECT exercises FROM event WHERE id = $1) || $2) WHERE id=$1;

-- name: UpdateEventLastAccessedDate :exec
UPDATE team SET last_access = $2 WHERE tag = $1;

-- name: UpdateTeamSolvedChl :exec
UPDATE team SET solved_challenges = $2 WHERE tag = $1;

-- name: UpdateTeamPassword :exec
UPDATE team SET password = $1 WHERE tag = $2 and event_id = $3;

-- name: TeamSolvedChls :many
SELECT solved_challenges FROM team WHERE tag=$1;

-- name: GetAllEvents :many
SELECT * FROM event;

-- name: GetAvailableEvents :many
SELECT id FROM event WHERE tag=$1 and finished_at = date('0001-01-01 00:00:00') and (status = 0 or status = 1 or status = 2);

-- name: GetTeamsForEvent :many
SELECT * FROM team WHERE event_id=$1;

-- name: GetTeamCount :many
SELECT count(team.id) FROM team WHERE team.event_id=$1;

-- name: GetEventStatus :many
SELECT status FROM event WHERE tag=$1;

-- name: GetEventsExeptClosed :many
SELECT * FROM event WHERE status!=3;

-- name: GetEventsByStatus :many
SELECT * FROM event WHERE status=$1;

-- name: GetEventsByUser :many
SELECT * FROM event WHERE status!=$1 and createdby=$2;

-- name: DoesEventExist :one
SELECT EXISTS (select tag from event where tag=$1 and status!=$2);

-- name: EarliestDate :one
SELECT started_at FROM event WHERE started_at=(SELECT MIN(started_at) FROM event) and finished_at = date('0001-01-01 00:00:00');

-- name: LatestDate :one
SELECT finish_expected FROM event WHERE finish_expected =(SELECT max(finish_expected) FROM event) and finished_at = date('0001-01-01 00:00:00');

-- name: DropEvent :exec
DELETE FROM event WHERE tag=$1 and status=$2;

-- name: GetExerciseDatabases :many
SELECT * FROM Exercise_dbs;

-- name: GetAdminUser :one
SELECT * FROM Admin_users WHERE LOWER(username)=LOWER($1);

-- name: GetRoleById :one
SELECT * FROM Roles WHERE id=$1;

-- name: GetOrgById :one
SELECT * FROM Organizations WHERE id=$1;

-- name: CreateAdminUser :exec
INSERT INTO Admin_users (username, password, email, role_id, organization_id) VALUES ($1, $2, $3, $4, $5);
