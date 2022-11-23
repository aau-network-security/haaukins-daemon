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