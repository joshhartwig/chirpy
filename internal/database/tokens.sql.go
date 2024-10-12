// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: tokens.sql

package database

import (
	"context"
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
    $3,
    $4
  )
RETURNING token, created_at, updated_at, expires_at, revoked_at, user_id
`

type CreateTokenParams struct {
	Token     string
	UserID    uuid.UUID
	ExpiresAt time.Time
	RevokedAt time.Time
}

func (q *Queries) CreateToken(ctx context.Context, arg CreateTokenParams) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, createToken,
		arg.Token,
		arg.UserID,
		arg.ExpiresAt,
		arg.RevokedAt,
	)
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
