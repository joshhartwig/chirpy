-- name: CreateToken :one
INSERT INTO refresh_tokens
  (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES
  (
    $1,
    NOW(),
    NOW(),
    $2,
    NOW() + INTERVAL
'60 days',
    NULL
  )
RETURNING *;

-- name: DeleteAllTokens :exec
DELETE FROM refresh_tokens
RETURNING *;

-- name: GetAllTokens :many
SELECT *
FROM refresh_tokens;

-- name: GetUserIDByToken :one
SELECT user_id
FROM refresh_tokens
WHERE token = $1;

-- name: GetTokenDetails :one
SELECT token, user_id, created_at, updated_at, expires_at, revoked_at
FROM refresh_tokens
WHERE token = $1
  AND revoked_at IS null
  AND expires_at > NOW();


-- name: RevokeToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(),
updated_at = NOW()
WHERE token = $1
RETURNING *;