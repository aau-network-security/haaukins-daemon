-- name: AddEvent :exec
INSERT INTO events (tag, name, available, capacity, frontend, status, exercises, started_at, finish_expected, finished_at, createdby, secretKey) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,$11,$12);

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

-- name: GetAvailableEvents :many
SELECT id FROM events WHERE tag=$1 and finished_at = date('0001-01-01 00:00:00') and (status = 0 or status = 1 or status = 2);


-- name: GetEventStatus :many
SELECT status FROM events WHERE tag=$1;

-- name: GetEventsExeptClosed :many
SELECT * FROM events WHERE status!=3;

-- name: GetEventsByStatus :many
SELECT * FROM events WHERE status=$1;

-- name: GetEventsByUser :many
SELECT * FROM events WHERE status!=$1 and createdby=$2;

-- name: DoesEventExist :one
SELECT EXISTS (select tag from events where tag=$1 and status!=$2);

-- name: EarliestDate :one
SELECT started_at FROM events WHERE started_at=(SELECT MIN(started_at) FROM events) and finished_at = date('0001-01-01 00:00:00');

-- name: LatestDate :one
SELECT finish_expected FROM events WHERE finish_expected =(SELECT max(finish_expected) FROM events) and finished_at = date('0001-01-01 00:00:00');

-- name: DropEvent :exec
DELETE FROM events WHERE tag=$1 and status=$2;