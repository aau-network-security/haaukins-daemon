-- name: GetAgents :many
SELECT * FROM agents;

-- name: GetAgentByName :one
SELECT * FROM agents WHERE lower(name) = lower(@name);

-- name: InsertNewAgent :exec
INSERT INTO agents (name, url, sign_key, auth_key, tls, statelock) VALUES (@name, @url, @signKey, @authKey, @tls, false);

-- name: CheckIfAgentExists :one
SELECT EXISTS( SELECT 1 FROM agents WHERE lower(name) = lower(@agentname) );

-- name: DeleteAgentByName :exec
DELETE FROM agents WHERE lower(name) = lower(@name);