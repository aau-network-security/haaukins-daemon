-- name: AddEvent :exec
INSERT INTO events (tag, name, initial_labs, max_labs, frontend, status, exercises, started_at, finish_expected, finished_at, createdby, secretKey) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,$11,$12);

-- name: UpdateCloseEvent :exec
UPDATE events SET tag = $2, finished_at = $3 WHERE tag = $1;

-- name: UpdateEventStatus :exec
UPDATE events SET status = $2 WHERE tag = $1;

-- name: UpdateExercises :exec
-- UPDATE event SET exercises = (SELECT (SELECT exercises FROM event WHERE id = $1) || $2) WHERE id=$1;

-- name: UpdateEventLastAccessedDate :exec
UPDATE teams SET last_access = $2 WHERE tag = $1;

-- name: GetAllEvents :many
SELECT * FROM events;

-- name: GetEventsExeptClosed :many
SELECT * FROM events WHERE status!=2;

-- name: GetEventStatus :many
SELECT status FROM events WHERE tag=$1;

-- name: GetEventsByStatus :many
SELECT * FROM events WHERE status=$1;

-- name: GetEventsByUser :many
SELECT * FROM events WHERE createdBy=$1;

-- name: CheckIfEventExist :one
SELECT EXISTS (select tag from events where tag=$1);

-- name: GetExpectedFinishDate :one
SELECT finish_expected FROM events WHERE tag=$1;

-- name: DeleteEventByTagAndStatus :exec
DELETE FROM events WHERE tag=$1 and status=$2;

-- name: DeleteEventOlderThan :exec
DELETE FROM events WHERE finished_at < GETDATE() - @numberOfDays and status = 2;