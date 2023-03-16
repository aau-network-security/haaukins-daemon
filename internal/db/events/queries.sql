-- name: AddEvent :one
INSERT INTO events (tag, type, name, organization, max_labs, frontend, status, exercises, public_scoreboard, dynamic_scoring, dynamic_max, dynamic_min, dynamic_solve_threshold, started_at, finish_expected, finished_at, createdby, secretKey) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) RETURNING id;

-- name: CloseEvent :exec
UPDATE events SET tag = @newTag, finished_at = @finishedAt, status = @newStatus WHERE tag = @oldTag;

-- name: UpdateEventStatus :exec
UPDATE events SET status = $2 WHERE tag = $1;

-- name: UpdateExercises :exec
-- UPDATE event SET exercises = (SELECT (SELECT exercises FROM event WHERE id = $1) || $2) WHERE id=$1;

-- name: UpdateEventLastAccessedDate :exec
UPDATE teams SET last_access = $2 WHERE tag = $1;

-- name: GetAllEvents :many
SELECT * FROM events;

-- name: GetOrgEvents :many
SELECT * FROM events WHERE organization = $1;

-- name: GetOrgEventsByCreatedBy :many
SELECT * FROM events WHERE organization = $1 AND createdBy = $2;

-- name: GetOrgEventsByStatus :many
SELECT * FROM events WHERE organization = $1 AND status = $2;

-- name: GetOrgEventsByStatusAndCreatedBy :many
SELECT * FROM events WHERE organization = $1 AND status = $2 AND createdBy = $3;

-- name: GetEventByTag :one
SELECT * FROM events WHERE tag = $1;

-- name: GetEventsExeptClosed :many
SELECT * FROM events WHERE status!=2;

-- name: GetEventStatusByTag :many
SELECT status FROM events WHERE tag=$1;

-- name: GetEventsByStatus :many
SELECT * FROM events WHERE status=$1;

-- name: GetEventsByUser :many
SELECT * FROM events WHERE createdBy=$1;

-- name: CheckIfEventExist :one
SELECT EXISTS (select tag from events where tag=$1);

-- name: GetExpectedFinishDate :one
SELECT finish_expected FROM events WHERE tag=$1;

-- name: DeleteEventByTag :exec
DELETE FROM events WHERE tag=$1;

-- name: DeleteEventOlderThan :exec
DELETE FROM events WHERE finished_at < GETDATE() - @numberOfDays and status = @closedStatus;