package db

import "context"

const getSolvesForEvent = `-- name: GetSolvesForEvent :many
SELECT tag, COUNT(tag) FROM solves WHERE event_id = $1 GROUP BY tag
`

type GetSolvesForEventRow struct {
	Tag   string
	Count int64
}

func (q *Queries) GetEventSolvesMap(ctx context.Context, eventId int32) (map[string]int64, error) {
	rows, err := q.db.QueryContext(ctx, getSolvesForEvent, eventId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make(map[string]int64)
	for rows.Next() {
		var i GetSolvesForEventRow
		if err := rows.Scan(&i.Tag, &i.Count); err != nil {
			return nil, err
		}
		items[i.Tag] = i.Count
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
