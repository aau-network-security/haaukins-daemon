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

-- name: GetAdminUser :one
SELECT * FROM Admin_users WHERE LOWER(username)=LOWER(@username);

-- name: GetOrgByName :one
SELECT * FROM Organizations WHERE LOWER(name)=LOWER(@orgName);

-- name: CreateAdminUser :exec
INSERT INTO Admin_users (username, password, full_name, email, role, organization) VALUES ($1, $2, $3, $4, $5, $6);

-- name: DeleteAdminUser :exec
DELETE FROM Admin_users WHERE LOWER(username)=LOWER($1);

-- name: GetAdminUserNoPw :one
SELECT username, full_name, email, role, organization FROM Admin_users WHERE LOWER(username)=LOWER($1);

-- name: GetAdminUsers :many
SELECT username, full_name, email, role, organization FROM Admin_users WHERE organization = CASE WHEN @organization='' THEN organization ELSE @organization END;

-- name: UpdateAdminPassword :exec
UPDATE Admin_users SET password = @password WHERE username = @username;

-- name: UpdateAdminEmail :exec
UPDATE Admin_users SET email = @email WHERE username = @username;

-- name: CheckIfUserExists :one
SELECT EXISTS( SELECT 1 FROM Admin_users WHERE lower(username) = lower(@username) );

-- name: CheckIfUserExistsInOrg :one
SELECT EXISTS( SELECT 1 FROM Admin_users WHERE lower(username) = lower(@username) AND lower(organization) = lower(@organization));

-- name: CheckIfOrgExists :one
SELECT EXISTS( SELECT 1 FROM Organizations WHERE lower(name) = lower(@orgName) );

-- name: AddOrganization :exec
INSERT INTO Organizations (name, owner_user, owner_email) VALUES (@org, @ownerUsername, @ownerEmail);

-- name: GetOrganizations :many
SELECT * FROM Organizations;

-- name: UpdateOrganization :exec
UPDATE Organizations SET owner_user = @ownerUsername, owner_email = @ownerEmail WHERE lower(name) = lower(@orgName);

-- name: DeleteOrganization :exec
DELETE FROM Organizations WHERE lower(name) = lower(@orgName);