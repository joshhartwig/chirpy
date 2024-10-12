-- name: CreateToken :one
INSERT INTO refresh_tokens
  (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES
  (
    $1,
    NOW(),
    NOW(),
    $2,
    $3,
    $4
  )
RETURNING *;

-- name: DeleteAllTokens :exec
DELETE FROM refresh_tokens
RETURNING *;

-- name: GetAllTokens :many
SELECT *
FROM refresh_tokens;