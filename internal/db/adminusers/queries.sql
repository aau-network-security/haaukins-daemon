-- name: GetAdminUserByUsername :one
SELECT * FROM admin_users WHERE LOWER(username)=LOWER(@username);

-- name: CreateAdminUser :exec
INSERT INTO admin_users (username, password, full_name, email, role, organization, lab_quota) VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: DeleteAdminUserByUsername :exec
DELETE FROM admin_users WHERE LOWER(username)=LOWER($1);

-- name: GetAdminUserNoPwByUsername :one
SELECT username, full_name, email, role, organization, lab_quota FROM admin_users WHERE LOWER(username)=LOWER($1);

-- name: GetAdminUserBySid :one
SELECT * from admin_users where sid::text = @sid::text;

-- name: GetAdminUsers :many
SELECT username, full_name, email, role, organization, lab_quota FROM admin_users WHERE LOWER(organization) = CASE WHEN @organization='' THEN LOWER(organization) ELSE LOWER(@organization) END;

-- name: UpdateAdminPassword :exec
UPDATE admin_users SET password = @password WHERE username = @username;

-- name: UpdateAdminEmail :exec
UPDATE admin_users SET email = @email WHERE username = @username;

-- name: UpdateAdminLabQuota :exec
UPDATE admin_users SET lab_quota = @labQuota WHERE username = @username;

-- name: CheckIfUserExists :one
SELECT EXISTS( SELECT 1 FROM admin_users WHERE lower(username) = lower(@username) );

-- name: CheckIfUserExistsInOrg :one
SELECT EXISTS( SELECT 1 FROM admin_users WHERE lower(username) = lower(@username) AND lower(organization) = lower(@organization));

-- name: UpdateAdminUserRoleByUsername :exec
UPDATE admin_users SET role = @role WHERE lower(username) = lower(@username);

-- name: UpdateAdminUserOrganizationByUsername :exec
UPDATE admin_users SET organization = @organization WHERE lower(username) = lower(@username);
