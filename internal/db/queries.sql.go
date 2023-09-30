// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.20.0
// source: queries.sql

package db

import (
	"context"
	"database/sql"
	"time"
)

const addEvent = `-- name: AddEvent :one
INSERT INTO events (tag, type, name, organization, max_labs, frontend, status, exercises, public_scoreboard, dynamic_scoring, dynamic_max, dynamic_min, dynamic_solve_threshold, started_at, finish_expected, finished_at, createdby, secretKey) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) RETURNING id
`

type AddEventParams struct {
	Tag                   string
	Type                  int32
	Name                  string
	Organization          string
	MaxLabs               int32
	Frontend              string
	Status                int32
	Exercises             string
	PublicScoreboard      bool
	DynamicScoring        bool
	DynamicMax            int32
	DynamicMin            int32
	DynamicSolveThreshold int32
	StartedAt             time.Time
	FinishExpected        time.Time
	FinishedAt            sql.NullTime
	Createdby             string
	Secretkey             string
}

func (q *Queries) AddEvent(ctx context.Context, arg AddEventParams) (int32, error) {
	row := q.db.QueryRowContext(ctx, addEvent,
		arg.Tag,
		arg.Type,
		arg.Name,
		arg.Organization,
		arg.MaxLabs,
		arg.Frontend,
		arg.Status,
		arg.Exercises,
		arg.PublicScoreboard,
		arg.DynamicScoring,
		arg.DynamicMax,
		arg.DynamicMin,
		arg.DynamicSolveThreshold,
		arg.StartedAt,
		arg.FinishExpected,
		arg.FinishedAt,
		arg.Createdby,
		arg.Secretkey,
	)
	var id int32
	err := row.Scan(&id)
	return id, err
}

const addOrganization = `-- name: AddOrganization :exec
INSERT INTO organizations (name, owner_user, owner_email) VALUES ($1, $2, $3)
`

type AddOrganizationParams struct {
	Org           string
	Ownerusername string
	Owneremail    string
}

func (q *Queries) AddOrganization(ctx context.Context, arg AddOrganizationParams) error {
	_, err := q.db.ExecContext(ctx, addOrganization, arg.Org, arg.Ownerusername, arg.Owneremail)
	return err
}

const addProfile = `-- name: AddProfile :one
INSERT INTO profiles (name, secret, organization, description, public) VALUES ($1, $2, $3, $4, $5) RETURNING id
`

type AddProfileParams struct {
	Profilename string
	Secret      bool
	Orgname     string
	Description string
	Public      bool
}

func (q *Queries) AddProfile(ctx context.Context, arg AddProfileParams) (int32, error) {
	row := q.db.QueryRowContext(ctx, addProfile,
		arg.Profilename,
		arg.Secret,
		arg.Orgname,
		arg.Description,
		arg.Public,
	)
	var id int32
	err := row.Scan(&id)
	return id, err
}

const addProfileChallenge = `-- name: AddProfileChallenge :exec
INSERT INTO profile_challenges (tag, name, profile_id) VALUES ($1, $2, $3)
`

type AddProfileChallengeParams struct {
	Tag       string
	Name      string
	Profileid int32
}

func (q *Queries) AddProfileChallenge(ctx context.Context, arg AddProfileChallengeParams) error {
	_, err := q.db.ExecContext(ctx, addProfileChallenge, arg.Tag, arg.Name, arg.Profileid)
	return err
}

const addSolveForTeamInEvent = `-- name: AddSolveForTeamInEvent :exec
INSERT INTO solves (tag, event_id, team_id, solved_at) VALUES ($1, $2, $3, $4)
`

type AddSolveForTeamInEventParams struct {
	Tag      string
	Eventid  int32
	Teamid   int32
	Solvedat time.Time
}

func (q *Queries) AddSolveForTeamInEvent(ctx context.Context, arg AddSolveForTeamInEventParams) error {
	_, err := q.db.ExecContext(ctx, addSolveForTeamInEvent,
		arg.Tag,
		arg.Eventid,
		arg.Teamid,
		arg.Solvedat,
	)
	return err
}

const addTeam = `-- name: AddTeam :exec
INSERT INTO teams (tag, event_id, email, username, password, created_at, last_access) VALUES ($1, $2, $3, $4, $5, $6, $7)
`

type AddTeamParams struct {
	Tag        string
	EventID    int32
	Email      string
	Username   string
	Password   string
	CreatedAt  time.Time
	LastAccess sql.NullTime
}

func (q *Queries) AddTeam(ctx context.Context, arg AddTeamParams) error {
	_, err := q.db.ExecContext(ctx, addTeam,
		arg.Tag,
		arg.EventID,
		arg.Email,
		arg.Username,
		arg.Password,
		arg.CreatedAt,
		arg.LastAccess,
	)
	return err
}

const checkIfAgentExists = `-- name: CheckIfAgentExists :one
SELECT EXISTS( SELECT 1 FROM agents WHERE lower(name) = lower($1) )
`

func (q *Queries) CheckIfAgentExists(ctx context.Context, agentname string) (bool, error) {
	row := q.db.QueryRowContext(ctx, checkIfAgentExists, agentname)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const checkIfEventExist = `-- name: CheckIfEventExist :one
SELECT EXISTS (select tag from events where tag=$1)
`

func (q *Queries) CheckIfEventExist(ctx context.Context, tag string) (bool, error) {
	row := q.db.QueryRowContext(ctx, checkIfEventExist, tag)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const checkIfOrgExists = `-- name: CheckIfOrgExists :one
SELECT EXISTS( SELECT 1 FROM organizations WHERE lower(name) = lower($1) )
`

func (q *Queries) CheckIfOrgExists(ctx context.Context, orgname string) (bool, error) {
	row := q.db.QueryRowContext(ctx, checkIfOrgExists, orgname)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const checkIfProfileExists = `-- name: CheckIfProfileExists :one
SELECT EXISTS(SELECT 1 FROM profiles WHERE lower(name) = lower($1) AND lower(organization) = lower($2))
`

type CheckIfProfileExistsParams struct {
	Profilename string
	Orgname     string
}

func (q *Queries) CheckIfProfileExists(ctx context.Context, arg CheckIfProfileExistsParams) (bool, error) {
	row := q.db.QueryRowContext(ctx, checkIfProfileExists, arg.Profilename, arg.Orgname)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const checkIfTeamExistsForEvent = `-- name: CheckIfTeamExistsForEvent :one
SELECT EXISTS( SELECT 1 FROM teams WHERE lower(username) = lower($1) AND event_id = $2)
`

type CheckIfTeamExistsForEventParams struct {
	Username string
	Eventid  int32
}

func (q *Queries) CheckIfTeamExistsForEvent(ctx context.Context, arg CheckIfTeamExistsForEventParams) (bool, error) {
	row := q.db.QueryRowContext(ctx, checkIfTeamExistsForEvent, arg.Username, arg.Eventid)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const checkIfUserExists = `-- name: CheckIfUserExists :one
SELECT EXISTS( SELECT 1 FROM admin_users WHERE lower(username) = lower($1) )
`

func (q *Queries) CheckIfUserExists(ctx context.Context, username string) (bool, error) {
	row := q.db.QueryRowContext(ctx, checkIfUserExists, username)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const checkIfUserExistsInOrg = `-- name: CheckIfUserExistsInOrg :one
SELECT EXISTS( SELECT 1 FROM admin_users WHERE lower(username) = lower($1) AND lower(organization) = lower($2))
`

type CheckIfUserExistsInOrgParams struct {
	Username     string
	Organization string
}

func (q *Queries) CheckIfUserExistsInOrg(ctx context.Context, arg CheckIfUserExistsInOrgParams) (bool, error) {
	row := q.db.QueryRowContext(ctx, checkIfUserExistsInOrg, arg.Username, arg.Organization)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const checkIfUserOwnsOrg = `-- name: CheckIfUserOwnsOrg :one
SELECT EXISTS( SELECT 1 FROM organizations WHERE lower(owner_user) = lower($1))
`

func (q *Queries) CheckIfUserOwnsOrg(ctx context.Context, ownerusername string) (bool, error) {
	row := q.db.QueryRowContext(ctx, checkIfUserOwnsOrg, ownerusername)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const closeEvent = `-- name: CloseEvent :exec
UPDATE events SET tag = $1, finished_at = $2, status = $3 WHERE tag = $4
`

type CloseEventParams struct {
	Newtag     string
	Finishedat sql.NullTime
	Newstatus  int32
	Oldtag     string
}

func (q *Queries) CloseEvent(ctx context.Context, arg CloseEventParams) error {
	_, err := q.db.ExecContext(ctx, closeEvent,
		arg.Newtag,
		arg.Finishedat,
		arg.Newstatus,
		arg.Oldtag,
	)
	return err
}

const createAdminUser = `-- name: CreateAdminUser :exec
INSERT INTO admin_users (username, password, full_name, email, role, organization) VALUES ($1, $2, $3, $4, $5, $6)
`

type CreateAdminUserParams struct {
	Username     string
	Password     string
	FullName     string
	Email        string
	Role         string
	Organization string
}

func (q *Queries) CreateAdminUser(ctx context.Context, arg CreateAdminUserParams) error {
	_, err := q.db.ExecContext(ctx, createAdminUser,
		arg.Username,
		arg.Password,
		arg.FullName,
		arg.Email,
		arg.Role,
		arg.Organization,
	)
	return err
}

const deleteAdminUserByUsername = `-- name: DeleteAdminUserByUsername :exec
DELETE FROM admin_users WHERE LOWER(username)=LOWER($1)
`

func (q *Queries) DeleteAdminUserByUsername(ctx context.Context, lower string) error {
	_, err := q.db.ExecContext(ctx, deleteAdminUserByUsername, lower)
	return err
}

const deleteAgentByName = `-- name: DeleteAgentByName :exec
DELETE FROM agents WHERE lower(name) = lower($1)
`

func (q *Queries) DeleteAgentByName(ctx context.Context, name string) error {
	_, err := q.db.ExecContext(ctx, deleteAgentByName, name)
	return err
}

const deleteEventById = `-- name: DeleteEventById :exec
DELETE FROM events WHERE id=$1
`

func (q *Queries) DeleteEventById(ctx context.Context, id int32) error {
	_, err := q.db.ExecContext(ctx, deleteEventById, id)
	return err
}

const deleteEventByTag = `-- name: DeleteEventByTag :exec
DELETE FROM events WHERE tag=$1
`

func (q *Queries) DeleteEventByTag(ctx context.Context, tag string) error {
	_, err := q.db.ExecContext(ctx, deleteEventByTag, tag)
	return err
}

const deleteEventOlderThan = `-- name: DeleteEventOlderThan :exec
DELETE FROM events WHERE finished_at < GETDATE() - $1 and status = $2
`

type DeleteEventOlderThanParams struct {
	Numberofdays interface{}
	Closedstatus int32
}

func (q *Queries) DeleteEventOlderThan(ctx context.Context, arg DeleteEventOlderThanParams) error {
	_, err := q.db.ExecContext(ctx, deleteEventOlderThan, arg.Numberofdays, arg.Closedstatus)
	return err
}

const deleteOrganization = `-- name: DeleteOrganization :exec
DELETE FROM organizations WHERE lower(name) = lower($1)
`

func (q *Queries) DeleteOrganization(ctx context.Context, orgname string) error {
	_, err := q.db.ExecContext(ctx, deleteOrganization, orgname)
	return err
}

const deleteProfile = `-- name: DeleteProfile :exec
DELETE FROM profiles WHERE lower(name) = lower($1) AND lower(organization) = lower($2)
`

type DeleteProfileParams struct {
	Profilename string
	Orgname     string
}

func (q *Queries) DeleteProfile(ctx context.Context, arg DeleteProfileParams) error {
	_, err := q.db.ExecContext(ctx, deleteProfile, arg.Profilename, arg.Orgname)
	return err
}

const deleteTeam = `-- name: DeleteTeam :exec
DELETE FROM teams WHERE tag=$1 and event_id = $2
`

type DeleteTeamParams struct {
	Tag     string
	EventID int32
}

func (q *Queries) DeleteTeam(ctx context.Context, arg DeleteTeamParams) error {
	_, err := q.db.ExecContext(ctx, deleteTeam, arg.Tag, arg.EventID)
	return err
}

const getAdminUserByUsername = `-- name: GetAdminUserByUsername :one
SELECT id, username, password, full_name, email, role, lab_quota, organization FROM admin_users WHERE LOWER(username)=LOWER($1)
`

func (q *Queries) GetAdminUserByUsername(ctx context.Context, username string) (AdminUser, error) {
	row := q.db.QueryRowContext(ctx, getAdminUserByUsername, username)
	var i AdminUser
	err := row.Scan(
		&i.ID,
		&i.Username,
		&i.Password,
		&i.FullName,
		&i.Email,
		&i.Role,
		&i.LabQuota,
		&i.Organization,
	)
	return i, err
}

const getAdminUserNoPwByUsername = `-- name: GetAdminUserNoPwByUsername :one
SELECT username, full_name, email, role, organization FROM admin_users WHERE LOWER(username)=LOWER($1)
`

type GetAdminUserNoPwByUsernameRow struct {
	Username     string
	FullName     string
	Email        string
	Role         string
	Organization string
}

func (q *Queries) GetAdminUserNoPwByUsername(ctx context.Context, lower string) (GetAdminUserNoPwByUsernameRow, error) {
	row := q.db.QueryRowContext(ctx, getAdminUserNoPwByUsername, lower)
	var i GetAdminUserNoPwByUsernameRow
	err := row.Scan(
		&i.Username,
		&i.FullName,
		&i.Email,
		&i.Role,
		&i.Organization,
	)
	return i, err
}

const getAdminUsers = `-- name: GetAdminUsers :many
SELECT username, full_name, email, role, organization FROM admin_users WHERE LOWER(organization) = CASE WHEN $1='' THEN LOWER(organization) ELSE LOWER($1) END
`

type GetAdminUsersRow struct {
	Username     string
	FullName     string
	Email        string
	Role         string
	Organization string
}

func (q *Queries) GetAdminUsers(ctx context.Context, organization interface{}) ([]GetAdminUsersRow, error) {
	rows, err := q.db.QueryContext(ctx, getAdminUsers, organization)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetAdminUsersRow
	for rows.Next() {
		var i GetAdminUsersRow
		if err := rows.Scan(
			&i.Username,
			&i.FullName,
			&i.Email,
			&i.Role,
			&i.Organization,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getAgentByName = `-- name: GetAgentByName :one
SELECT id, name, url, weight, sign_key, auth_key, tls, statelock FROM agents WHERE lower(name) = lower($1)
`

func (q *Queries) GetAgentByName(ctx context.Context, name string) (Agent, error) {
	row := q.db.QueryRowContext(ctx, getAgentByName, name)
	var i Agent
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Url,
		&i.Weight,
		&i.SignKey,
		&i.AuthKey,
		&i.Tls,
		&i.Statelock,
	)
	return i, err
}

const getAgents = `-- name: GetAgents :many
SELECT id, name, url, weight, sign_key, auth_key, tls, statelock FROM agents
`

func (q *Queries) GetAgents(ctx context.Context) ([]Agent, error) {
	rows, err := q.db.QueryContext(ctx, getAgents)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Agent
	for rows.Next() {
		var i Agent
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Url,
			&i.Weight,
			&i.SignKey,
			&i.AuthKey,
			&i.Tls,
			&i.Statelock,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getAllEvents = `-- name: GetAllEvents :many
SELECT id, tag, type, organization, name, max_labs, status, frontend, exercises, public_scoreboard, dynamic_scoring, dynamic_max, dynamic_min, dynamic_solve_threshold, started_at, finish_expected, finished_at, createdby, secretkey FROM events
`

func (q *Queries) GetAllEvents(ctx context.Context) ([]Event, error) {
	rows, err := q.db.QueryContext(ctx, getAllEvents)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Event
	for rows.Next() {
		var i Event
		if err := rows.Scan(
			&i.ID,
			&i.Tag,
			&i.Type,
			&i.Organization,
			&i.Name,
			&i.MaxLabs,
			&i.Status,
			&i.Frontend,
			&i.Exercises,
			&i.PublicScoreboard,
			&i.DynamicScoring,
			&i.DynamicMax,
			&i.DynamicMin,
			&i.DynamicSolveThreshold,
			&i.StartedAt,
			&i.FinishExpected,
			&i.FinishedAt,
			&i.Createdby,
			&i.Secretkey,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getAllProfilesInOrg = `-- name: GetAllProfilesInOrg :many
SELECT id, name, secret, description, public, organization FROM profiles WHERE lower(organization) = lower($1) AND public = FALSE
`

func (q *Queries) GetAllProfilesInOrg(ctx context.Context, orgname string) ([]Profile, error) {
	rows, err := q.db.QueryContext(ctx, getAllProfilesInOrg, orgname)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Profile
	for rows.Next() {
		var i Profile
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Secret,
			&i.Description,
			&i.Public,
			&i.Organization,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getAllPublicProfiles = `-- name: GetAllPublicProfiles :many
SELECT id, name, secret, description, public, organization FROM profiles WHERE public = TRUE
`

func (q *Queries) GetAllPublicProfiles(ctx context.Context) ([]Profile, error) {
	rows, err := q.db.QueryContext(ctx, getAllPublicProfiles)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Profile
	for rows.Next() {
		var i Profile
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Secret,
			&i.Description,
			&i.Public,
			&i.Organization,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getEventByTag = `-- name: GetEventByTag :one
SELECT id, tag, type, organization, name, max_labs, status, frontend, exercises, public_scoreboard, dynamic_scoring, dynamic_max, dynamic_min, dynamic_solve_threshold, started_at, finish_expected, finished_at, createdby, secretkey FROM events WHERE tag = $1
`

func (q *Queries) GetEventByTag(ctx context.Context, tag string) (Event, error) {
	row := q.db.QueryRowContext(ctx, getEventByTag, tag)
	var i Event
	err := row.Scan(
		&i.ID,
		&i.Tag,
		&i.Type,
		&i.Organization,
		&i.Name,
		&i.MaxLabs,
		&i.Status,
		&i.Frontend,
		&i.Exercises,
		&i.PublicScoreboard,
		&i.DynamicScoring,
		&i.DynamicMax,
		&i.DynamicMin,
		&i.DynamicSolveThreshold,
		&i.StartedAt,
		&i.FinishExpected,
		&i.FinishedAt,
		&i.Createdby,
		&i.Secretkey,
	)
	return i, err
}

const getEventSolves = `-- name: GetEventSolves :many
SELECT solves.tag, solves.solved_at, teams.username FROM solves INNER JOIN teams ON solves.team_id = teams.id WHERE solves.event_id = $1 ORDER BY solves.solved_at ASC
`

type GetEventSolvesRow struct {
	Tag      string
	SolvedAt time.Time
	Username string
}

func (q *Queries) GetEventSolves(ctx context.Context, eventID int32) ([]GetEventSolvesRow, error) {
	rows, err := q.db.QueryContext(ctx, getEventSolves, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetEventSolvesRow
	for rows.Next() {
		var i GetEventSolvesRow
		if err := rows.Scan(&i.Tag, &i.SolvedAt, &i.Username); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getEventStatusByTag = `-- name: GetEventStatusByTag :many
SELECT status FROM events WHERE tag=$1
`

func (q *Queries) GetEventStatusByTag(ctx context.Context, tag string) ([]int32, error) {
	rows, err := q.db.QueryContext(ctx, getEventStatusByTag, tag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []int32
	for rows.Next() {
		var status int32
		if err := rows.Scan(&status); err != nil {
			return nil, err
		}
		items = append(items, status)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getEventsByStatus = `-- name: GetEventsByStatus :many
SELECT id, tag, type, organization, name, max_labs, status, frontend, exercises, public_scoreboard, dynamic_scoring, dynamic_max, dynamic_min, dynamic_solve_threshold, started_at, finish_expected, finished_at, createdby, secretkey FROM events WHERE status=$1
`

func (q *Queries) GetEventsByStatus(ctx context.Context, status int32) ([]Event, error) {
	rows, err := q.db.QueryContext(ctx, getEventsByStatus, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Event
	for rows.Next() {
		var i Event
		if err := rows.Scan(
			&i.ID,
			&i.Tag,
			&i.Type,
			&i.Organization,
			&i.Name,
			&i.MaxLabs,
			&i.Status,
			&i.Frontend,
			&i.Exercises,
			&i.PublicScoreboard,
			&i.DynamicScoring,
			&i.DynamicMax,
			&i.DynamicMin,
			&i.DynamicSolveThreshold,
			&i.StartedAt,
			&i.FinishExpected,
			&i.FinishedAt,
			&i.Createdby,
			&i.Secretkey,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getEventsByUser = `-- name: GetEventsByUser :many
SELECT id, tag, type, organization, name, max_labs, status, frontend, exercises, public_scoreboard, dynamic_scoring, dynamic_max, dynamic_min, dynamic_solve_threshold, started_at, finish_expected, finished_at, createdby, secretkey FROM events WHERE createdBy=$1
`

func (q *Queries) GetEventsByUser(ctx context.Context, createdby string) ([]Event, error) {
	rows, err := q.db.QueryContext(ctx, getEventsByUser, createdby)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Event
	for rows.Next() {
		var i Event
		if err := rows.Scan(
			&i.ID,
			&i.Tag,
			&i.Type,
			&i.Organization,
			&i.Name,
			&i.MaxLabs,
			&i.Status,
			&i.Frontend,
			&i.Exercises,
			&i.PublicScoreboard,
			&i.DynamicScoring,
			&i.DynamicMax,
			&i.DynamicMin,
			&i.DynamicSolveThreshold,
			&i.StartedAt,
			&i.FinishExpected,
			&i.FinishedAt,
			&i.Createdby,
			&i.Secretkey,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getEventsExeptClosed = `-- name: GetEventsExeptClosed :many
SELECT id, tag, type, organization, name, max_labs, status, frontend, exercises, public_scoreboard, dynamic_scoring, dynamic_max, dynamic_min, dynamic_solve_threshold, started_at, finish_expected, finished_at, createdby, secretkey FROM events WHERE status!=2
`

func (q *Queries) GetEventsExeptClosed(ctx context.Context) ([]Event, error) {
	rows, err := q.db.QueryContext(ctx, getEventsExeptClosed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Event
	for rows.Next() {
		var i Event
		if err := rows.Scan(
			&i.ID,
			&i.Tag,
			&i.Type,
			&i.Organization,
			&i.Name,
			&i.MaxLabs,
			&i.Status,
			&i.Frontend,
			&i.Exercises,
			&i.PublicScoreboard,
			&i.DynamicScoring,
			&i.DynamicMax,
			&i.DynamicMin,
			&i.DynamicSolveThreshold,
			&i.StartedAt,
			&i.FinishExpected,
			&i.FinishedAt,
			&i.Createdby,
			&i.Secretkey,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getExercisesInProfile = `-- name: GetExercisesInProfile :many
SELECT profile_challenges.id, profile_challenges.tag, profile_challenges.name  FROM profiles INNER JOIN profile_challenges ON profiles.id = profile_challenges.profile_id WHERE profiles.id = $1 AND profiles.organization = $2 ORDER BY profiles.id asc
`

type GetExercisesInProfileParams struct {
	Profileid int32
	Orgname   string
}

type GetExercisesInProfileRow struct {
	ID   int32
	Tag  string
	Name string
}

func (q *Queries) GetExercisesInProfile(ctx context.Context, arg GetExercisesInProfileParams) ([]GetExercisesInProfileRow, error) {
	rows, err := q.db.QueryContext(ctx, getExercisesInProfile, arg.Profileid, arg.Orgname)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetExercisesInProfileRow
	for rows.Next() {
		var i GetExercisesInProfileRow
		if err := rows.Scan(&i.ID, &i.Tag, &i.Name); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getExpectedFinishDate = `-- name: GetExpectedFinishDate :one
SELECT finish_expected FROM events WHERE tag=$1
`

func (q *Queries) GetExpectedFinishDate(ctx context.Context, tag string) (time.Time, error) {
	row := q.db.QueryRowContext(ctx, getExpectedFinishDate, tag)
	var finish_expected time.Time
	err := row.Scan(&finish_expected)
	return finish_expected, err
}

const getNonSecretProfilesInOrg = `-- name: GetNonSecretProfilesInOrg :many
SELECT id, name, secret, description, public, organization FROM profiles WHERE lower(organization) = lower($1) and secret = FALSE AND public = FALSE
`

func (q *Queries) GetNonSecretProfilesInOrg(ctx context.Context, orgname string) ([]Profile, error) {
	rows, err := q.db.QueryContext(ctx, getNonSecretProfilesInOrg, orgname)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Profile
	for rows.Next() {
		var i Profile
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Secret,
			&i.Description,
			&i.Public,
			&i.Organization,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getNonSecretPublicProfiles = `-- name: GetNonSecretPublicProfiles :many
SELECT id, name, secret, description, public, organization FROM profiles WHERE secret = FALSE AND public = TRUE
`

func (q *Queries) GetNonSecretPublicProfiles(ctx context.Context) ([]Profile, error) {
	rows, err := q.db.QueryContext(ctx, getNonSecretPublicProfiles)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Profile
	for rows.Next() {
		var i Profile
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Secret,
			&i.Description,
			&i.Public,
			&i.Organization,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getOrgByName = `-- name: GetOrgByName :one
SELECT id, name, owner_user, owner_email, lab_quota FROM organizations WHERE LOWER(name)=LOWER($1)
`

func (q *Queries) GetOrgByName(ctx context.Context, orgname string) (Organization, error) {
	row := q.db.QueryRowContext(ctx, getOrgByName, orgname)
	var i Organization
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.OwnerUser,
		&i.OwnerEmail,
		&i.LabQuota,
	)
	return i, err
}

const getOrgEvents = `-- name: GetOrgEvents :many
SELECT id, tag, type, organization, name, max_labs, status, frontend, exercises, public_scoreboard, dynamic_scoring, dynamic_max, dynamic_min, dynamic_solve_threshold, started_at, finish_expected, finished_at, createdby, secretkey FROM events WHERE organization = $1
`

func (q *Queries) GetOrgEvents(ctx context.Context, organization string) ([]Event, error) {
	rows, err := q.db.QueryContext(ctx, getOrgEvents, organization)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Event
	for rows.Next() {
		var i Event
		if err := rows.Scan(
			&i.ID,
			&i.Tag,
			&i.Type,
			&i.Organization,
			&i.Name,
			&i.MaxLabs,
			&i.Status,
			&i.Frontend,
			&i.Exercises,
			&i.PublicScoreboard,
			&i.DynamicScoring,
			&i.DynamicMax,
			&i.DynamicMin,
			&i.DynamicSolveThreshold,
			&i.StartedAt,
			&i.FinishExpected,
			&i.FinishedAt,
			&i.Createdby,
			&i.Secretkey,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getOrgEventsByCreatedBy = `-- name: GetOrgEventsByCreatedBy :many
SELECT id, tag, type, organization, name, max_labs, status, frontend, exercises, public_scoreboard, dynamic_scoring, dynamic_max, dynamic_min, dynamic_solve_threshold, started_at, finish_expected, finished_at, createdby, secretkey FROM events WHERE organization = $1 AND createdBy = $2
`

type GetOrgEventsByCreatedByParams struct {
	Organization string
	Createdby    string
}

func (q *Queries) GetOrgEventsByCreatedBy(ctx context.Context, arg GetOrgEventsByCreatedByParams) ([]Event, error) {
	rows, err := q.db.QueryContext(ctx, getOrgEventsByCreatedBy, arg.Organization, arg.Createdby)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Event
	for rows.Next() {
		var i Event
		if err := rows.Scan(
			&i.ID,
			&i.Tag,
			&i.Type,
			&i.Organization,
			&i.Name,
			&i.MaxLabs,
			&i.Status,
			&i.Frontend,
			&i.Exercises,
			&i.PublicScoreboard,
			&i.DynamicScoring,
			&i.DynamicMax,
			&i.DynamicMin,
			&i.DynamicSolveThreshold,
			&i.StartedAt,
			&i.FinishExpected,
			&i.FinishedAt,
			&i.Createdby,
			&i.Secretkey,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getOrgEventsByStatus = `-- name: GetOrgEventsByStatus :many
SELECT id, tag, type, organization, name, max_labs, status, frontend, exercises, public_scoreboard, dynamic_scoring, dynamic_max, dynamic_min, dynamic_solve_threshold, started_at, finish_expected, finished_at, createdby, secretkey FROM events WHERE organization = $1 AND status = $2
`

type GetOrgEventsByStatusParams struct {
	Organization string
	Status       int32
}

func (q *Queries) GetOrgEventsByStatus(ctx context.Context, arg GetOrgEventsByStatusParams) ([]Event, error) {
	rows, err := q.db.QueryContext(ctx, getOrgEventsByStatus, arg.Organization, arg.Status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Event
	for rows.Next() {
		var i Event
		if err := rows.Scan(
			&i.ID,
			&i.Tag,
			&i.Type,
			&i.Organization,
			&i.Name,
			&i.MaxLabs,
			&i.Status,
			&i.Frontend,
			&i.Exercises,
			&i.PublicScoreboard,
			&i.DynamicScoring,
			&i.DynamicMax,
			&i.DynamicMin,
			&i.DynamicSolveThreshold,
			&i.StartedAt,
			&i.FinishExpected,
			&i.FinishedAt,
			&i.Createdby,
			&i.Secretkey,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getOrgEventsByStatusAndCreatedBy = `-- name: GetOrgEventsByStatusAndCreatedBy :many
SELECT id, tag, type, organization, name, max_labs, status, frontend, exercises, public_scoreboard, dynamic_scoring, dynamic_max, dynamic_min, dynamic_solve_threshold, started_at, finish_expected, finished_at, createdby, secretkey FROM events WHERE organization = $1 AND status = $2 AND createdBy = $3
`

type GetOrgEventsByStatusAndCreatedByParams struct {
	Organization string
	Status       int32
	Createdby    string
}

func (q *Queries) GetOrgEventsByStatusAndCreatedBy(ctx context.Context, arg GetOrgEventsByStatusAndCreatedByParams) ([]Event, error) {
	rows, err := q.db.QueryContext(ctx, getOrgEventsByStatusAndCreatedBy, arg.Organization, arg.Status, arg.Createdby)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Event
	for rows.Next() {
		var i Event
		if err := rows.Scan(
			&i.ID,
			&i.Tag,
			&i.Type,
			&i.Organization,
			&i.Name,
			&i.MaxLabs,
			&i.Status,
			&i.Frontend,
			&i.Exercises,
			&i.PublicScoreboard,
			&i.DynamicScoring,
			&i.DynamicMax,
			&i.DynamicMin,
			&i.DynamicSolveThreshold,
			&i.StartedAt,
			&i.FinishExpected,
			&i.FinishedAt,
			&i.Createdby,
			&i.Secretkey,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getOrganizations = `-- name: GetOrganizations :many
SELECT id, name, owner_user, owner_email, lab_quota FROM organizations
`

func (q *Queries) GetOrganizations(ctx context.Context) ([]Organization, error) {
	rows, err := q.db.QueryContext(ctx, getOrganizations)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Organization
	for rows.Next() {
		var i Organization
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.OwnerUser,
			&i.OwnerEmail,
			&i.LabQuota,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getProfileByNameAndOrgName = `-- name: GetProfileByNameAndOrgName :one
SELECT id, name, secret, description, public, organization FROM profiles WHERE lower(name) = $1 AND lower(organization) = lower($2)
`

type GetProfileByNameAndOrgNameParams struct {
	Profilename string
	Orgname     string
}

func (q *Queries) GetProfileByNameAndOrgName(ctx context.Context, arg GetProfileByNameAndOrgNameParams) (Profile, error) {
	row := q.db.QueryRowContext(ctx, getProfileByNameAndOrgName, arg.Profilename, arg.Orgname)
	var i Profile
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Secret,
		&i.Description,
		&i.Public,
		&i.Organization,
	)
	return i, err
}

const getProfiles = `-- name: GetProfiles :many
SELECT id, name, secret, description, public, organization FROM profiles
`

func (q *Queries) GetProfiles(ctx context.Context) ([]Profile, error) {
	rows, err := q.db.QueryContext(ctx, getProfiles)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Profile
	for rows.Next() {
		var i Profile
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Secret,
			&i.Description,
			&i.Public,
			&i.Organization,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getTeamCount = `-- name: GetTeamCount :one
SELECT count(teams.id) FROM teams WHERE teams.event_id=$1
`

func (q *Queries) GetTeamCount(ctx context.Context, eventID int32) (int64, error) {
	row := q.db.QueryRowContext(ctx, getTeamCount, eventID)
	var count int64
	err := row.Scan(&count)
	return count, err
}

const getTeamFromEventByUsername = `-- name: GetTeamFromEventByUsername :one
SELECT id, tag, event_id, email, username, password, created_at, last_access FROM teams WHERE lower(username) = lower($1) AND event_id = $2
`

type GetTeamFromEventByUsernameParams struct {
	Username string
	Eventid  int32
}

func (q *Queries) GetTeamFromEventByUsername(ctx context.Context, arg GetTeamFromEventByUsernameParams) (Team, error) {
	row := q.db.QueryRowContext(ctx, getTeamFromEventByUsername, arg.Username, arg.Eventid)
	var i Team
	err := row.Scan(
		&i.ID,
		&i.Tag,
		&i.EventID,
		&i.Email,
		&i.Username,
		&i.Password,
		&i.CreatedAt,
		&i.LastAccess,
	)
	return i, err
}

const getTeamFromEventByUsernameNoPw = `-- name: GetTeamFromEventByUsernameNoPw :one
SELECT (username, email) FROM teams WHERE lower(username) = lower($1) AND event_id = $2
`

type GetTeamFromEventByUsernameNoPwParams struct {
	Username string
	Eventid  int32
}

func (q *Queries) GetTeamFromEventByUsernameNoPw(ctx context.Context, arg GetTeamFromEventByUsernameNoPwParams) (interface{}, error) {
	row := q.db.QueryRowContext(ctx, getTeamFromEventByUsernameNoPw, arg.Username, arg.Eventid)
	var column_1 interface{}
	err := row.Scan(&column_1)
	return column_1, err
}

const getTeamsForEvent = `-- name: GetTeamsForEvent :many
SELECT id, tag, event_id, email, username, password, created_at, last_access FROM teams WHERE event_id=$1
`

func (q *Queries) GetTeamsForEvent(ctx context.Context, eventID int32) ([]Team, error) {
	rows, err := q.db.QueryContext(ctx, getTeamsForEvent, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Team
	for rows.Next() {
		var i Team
		if err := rows.Scan(
			&i.ID,
			&i.Tag,
			&i.EventID,
			&i.Email,
			&i.Username,
			&i.Password,
			&i.CreatedAt,
			&i.LastAccess,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const insertNewAgent = `-- name: InsertNewAgent :exec
INSERT INTO agents (name, url, weight, sign_key, auth_key, tls, statelock) VALUES ($1, $2, $3, $4, $5, $6, false)
`

type InsertNewAgentParams struct {
	Name    string
	Url     string
	Weight  int32
	Signkey string
	Authkey string
	Tls     bool
}

func (q *Queries) InsertNewAgent(ctx context.Context, arg InsertNewAgentParams) error {
	_, err := q.db.ExecContext(ctx, insertNewAgent,
		arg.Name,
		arg.Url,
		arg.Weight,
		arg.Signkey,
		arg.Authkey,
		arg.Tls,
	)
	return err
}

const updateAdminEmail = `-- name: UpdateAdminEmail :exec
UPDATE admin_users SET email = $1 WHERE username = $2
`

type UpdateAdminEmailParams struct {
	Email    string
	Username string
}

func (q *Queries) UpdateAdminEmail(ctx context.Context, arg UpdateAdminEmailParams) error {
	_, err := q.db.ExecContext(ctx, updateAdminEmail, arg.Email, arg.Username)
	return err
}

const updateAdminPassword = `-- name: UpdateAdminPassword :exec
UPDATE admin_users SET password = $1 WHERE username = $2
`

type UpdateAdminPasswordParams struct {
	Password string
	Username string
}

func (q *Queries) UpdateAdminPassword(ctx context.Context, arg UpdateAdminPasswordParams) error {
	_, err := q.db.ExecContext(ctx, updateAdminPassword, arg.Password, arg.Username)
	return err
}

const updateEventStatus = `-- name: UpdateEventStatus :exec
UPDATE events SET status = $2 WHERE tag = $1
`

type UpdateEventStatusParams struct {
	Tag    string
	Status int32
}

func (q *Queries) UpdateEventStatus(ctx context.Context, arg UpdateEventStatusParams) error {
	_, err := q.db.ExecContext(ctx, updateEventStatus, arg.Tag, arg.Status)
	return err
}

const updateExercises = `-- name: UpdateExercises :exec

UPDATE teams SET last_access = $2 WHERE tag = $1
`

type UpdateExercisesParams struct {
	Tag        string
	LastAccess sql.NullTime
}

// UPDATE event SET exercises = (SELECT (SELECT exercises FROM event WHERE id = $1) || $2) WHERE id=$1;
func (q *Queries) UpdateExercises(ctx context.Context, arg UpdateExercisesParams) error {
	_, err := q.db.ExecContext(ctx, updateExercises, arg.Tag, arg.LastAccess)
	return err
}

const updateOrganization = `-- name: UpdateOrganization :exec
UPDATE organizations SET owner_user = $1, owner_email = $2 WHERE lower(name) = lower($3)
`

type UpdateOrganizationParams struct {
	Ownerusername string
	Owneremail    string
	Orgname       string
}

func (q *Queries) UpdateOrganization(ctx context.Context, arg UpdateOrganizationParams) error {
	_, err := q.db.ExecContext(ctx, updateOrganization, arg.Ownerusername, arg.Owneremail, arg.Orgname)
	return err
}

const updateTeamPassword = `-- name: UpdateTeamPassword :exec
UPDATE teams SET password = $1 WHERE tag = $2 and event_id = $3
`

type UpdateTeamPasswordParams struct {
	Password string
	Tag      string
	EventID  int32
}

func (q *Queries) UpdateTeamPassword(ctx context.Context, arg UpdateTeamPasswordParams) error {
	_, err := q.db.ExecContext(ctx, updateTeamPassword, arg.Password, arg.Tag, arg.EventID)
	return err
}
