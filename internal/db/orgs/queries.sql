-- name: CheckIfOrgExists :one
SELECT EXISTS( SELECT 1 FROM organizations WHERE lower(name) = lower(@orgName) );

-- name: CheckIfUserOwnsOrg :one
SELECT EXISTS( SELECT 1 FROM organizations WHERE lower(owner_user) = lower(@ownerUsername));

-- name: AddOrganization :exec
INSERT INTO organizations (name, owner_user, owner_email) VALUES (@org, @ownerUsername, @ownerEmail);

-- name: GetOrganizations :many
SELECT * FROM organizations;

-- name: UpdateOrganization :exec
UPDATE organizations SET owner_user = @ownerUsername, owner_email = @ownerEmail WHERE lower(name) = lower(@orgName);

-- name: DeleteOrganization :exec
DELETE FROM organizations WHERE lower(name) = lower(@orgName);

-- name: GetOrgByName :one
SELECT * FROM organizations WHERE LOWER(name)=LOWER(@orgName);