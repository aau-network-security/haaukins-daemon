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
