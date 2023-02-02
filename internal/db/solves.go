package db

import (
	"context"
	"time"
)

const getSolvesForEvent = `-- name: GetSolvesForEvent :many
SELECT solves.tag, solves.solved_at, teams.username FROM solves INNER JOIN teams ON solves.team_id = teams.id WHERE solves.event_id = $1
`

type GetSolvesForEventRow struct {
	Tag  string
	Date time.Time
	Username string
}

func (q *Queries) GetEventSolvesMap(ctx context.Context, eventId int32) (map[string][]GetSolvesForEventRow, error) {
	rows, err := q.db.QueryContext(ctx, getSolvesForEvent, eventId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make(map[string][]GetSolvesForEventRow)
	for rows.Next() {
		var i GetSolvesForEventRow
		if err := rows.Scan(&i.Tag, &i.Date, &i.Username); err != nil {
			return nil, err
		}
		items[i.Tag] = append(items[i.Tag], i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getTeamSolves = `-- name: GetTeamSolves :many
SELECT id, tag, event_id, team_id, solved_at FROM solves WHERE team_id = $1
`

func (q *Queries) GetTeamSolvesMap(ctx context.Context, teamid int32) (map[string]bool, error) {
	rows, err := q.db.QueryContext(ctx, getTeamSolves, teamid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make(map[string]bool)
	for rows.Next() {
		var i Solf
		if err := rows.Scan(
			&i.ID,
			&i.Tag,
			&i.EventID,
			&i.TeamID,
			&i.SolvedAt,
		); err != nil {
			return nil, err
		}
		items[i.Tag] = true
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
