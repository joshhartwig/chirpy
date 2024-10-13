// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: tokens.sql

package database

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

const createToken = `-- name: CreateToken :one
INSERT INTO refresh_tokens
  (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES
  (
    $1,
    NOW(),
    NOW(),
    $2,
    NOW + INTERVAL
'60 day',
    null
  )
RETURNING token, created_at, updated_at, expires_at, revoked_at, user_id
`

type CreateTokenParams struct {
	Token  string
	UserID uuid.UUID
}

func (q *Queries) CreateToken(ctx context.Context, arg CreateTokenParams) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, createToken, arg.Token, arg.UserID)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.ExpiresAt,
		&i.RevokedAt,
		&i.UserID,
	)
	return i, err
}

const deleteAllTokens = `-- name: DeleteAllTokens :exec
DELETE FROM refresh_tokens
RETURNING token, created_at, updated_at, expires_at, revoked_at, user_id
`

func (q *Queries) DeleteAllTokens(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllTokens)
	return err
}

const getAllTokens = `-- name: GetAllTokens :many
SELECT token, created_at, updated_at, expires_at, revoked_at, user_id
FROM refresh_tokens
`

func (q *Queries) GetAllTokens(ctx context.Context) ([]RefreshToken, error) {
	rows, err := q.db.QueryContext(ctx, getAllTokens)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []RefreshToken
	for rows.Next() {
		var i RefreshToken
		if err := rows.Scan(
			&i.Token,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.ExpiresAt,
			&i.RevokedAt,
			&i.UserID,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getTokenDetails = `-- name: GetTokenDetails :one
SELECT token, user_id, created_at, updated_at, expires_at, revoked_at
FROM refresh_tokens
WHERE token = $1
  AND revoked_at IS null
  AND expires_at > NOW()
`

type GetTokenDetailsRow struct {
	Token     string
	UserID    uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
	RevokedAt sql.NullTime
}

func (q *Queries) GetTokenDetails(ctx context.Context, token string) (GetTokenDetailsRow, error) {
	row := q.db.QueryRowContext(ctx, getTokenDetails, token)
	var i GetTokenDetailsRow
	err := row.Scan(
		&i.Token,
		&i.UserID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const getUserIDByToken = `-- name: GetUserIDByToken :one
SELECT user_id
FROM refresh_tokens
WHERE token = $1
`

func (q *Queries) GetUserIDByToken(ctx context.Context, token string) (uuid.UUID, error) {
	row := q.db.QueryRowContext(ctx, getUserIDByToken, token)
	var user_id uuid.UUID
	err := row.Scan(&user_id)
	return user_id, err
}

const revokeToken = `-- name: RevokeToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(),
updated_at = NOW()
WHERE token = $1
RETURNING token, created_at, updated_at, expires_at, revoked_at, user_id
`

func (q *Queries) RevokeToken(ctx context.Context, token string) error {
	_, err := q.db.ExecContext(ctx, revokeToken, token)
	return err
}
