-- name: GetAdminUserByUsername :one
SELECT * FROM admin_users WHERE LOWER(username)=LOWER(@username);

-- name: CreateAdminUser :exec
INSERT INTO admin_users (username, password, full_name, email, role, organization) VALUES ($1, $2, $3, $4, $5, $6);

-- name: DeleteAdminUserByUsername :exec
DELETE FROM admin_users WHERE LOWER(username)=LOWER($1);

-- name: GetAdminUserNoPwByUsername :one
SELECT username, full_name, email, role, organization FROM admin_users WHERE LOWER(username)=LOWER($1);

-- name: GetAdminUsers :many
SELECT username, full_name, email, role, organization FROM admin_users WHERE organization = CASE WHEN @organization='' THEN organization ELSE @organization END;

-- name: UpdateAdminPassword :exec
UPDATE admin_users SET password = @password WHERE username = @username;

-- name: UpdateAdminEmail :exec
UPDATE admin_users SET email = @email WHERE username = @username;

-- name: CheckIfUserExists :one
SELECT EXISTS( SELECT 1 FROM admin_users WHERE lower(username) = lower(@username) );

-- name: CheckIfUserExistsInOrg :one
SELECT EXISTS( SELECT 1 FROM admin_users WHERE lower(username) = lower(@username) AND lower(organization) = lower(@organization));
