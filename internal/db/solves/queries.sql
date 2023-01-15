-- name: AddSolveForTeamInEvent :exec
INSERT INTO solves (tag, event_id, team_id, solved_at) VALUES (@tag, @eventId, @teamId, @solvedAt);