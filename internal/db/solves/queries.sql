-- name: AddSolveForTeamInEvent :exec
INSERT INTO solves (tag, event_id, team_id, solved_at) VALUES (@tag, @eventId, @teamId, @solvedAt);

-- name: GetEventSolves :many
SELECT solves.tag, solves.solved_at, teams.username FROM solves INNER JOIN teams ON solves.team_id = teams.id WHERE solves.event_id = $1 ORDER BY solves.solved_at ASC;