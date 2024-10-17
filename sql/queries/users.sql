-- name: CreateUser :one
INSERT INTO users
  (id, created_at, updated_at, email, hashed_password)
VALUES
  (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
  )
RETURNING *;

-- name: DeleteAllUsers :exec
DELETE FROM users
RETURNING *;

-- name: GetAllUsers :many
SELECT *
FROM users;

-- name: GetUserByEmail :one
SELECT *
FROM users
WHERE email = $1;

-- name: UpdateUserPassword :exec
UPDATE users
SET hashed_password = $1, updated_at = NOW()
WHERE id = $2;

-- name: UpgradeUserToChirpyRed :exec
UPDATE users
SET is_chirpy_red = TRUE, updated_at = NOW()
WHERE id = $1;

-- name: GetUserByID :one
SELECT *
FROM users
WHERE id = $1;