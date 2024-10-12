-- +goose Up
ALTER TABLE refresh_tokens
ALTER COLUMN revoked_at DROP NOT NULL;

-- +goose Down
ALTER TABLE refresh_tokens
ALTER COLUMN revoked_at
SET
NOT NULL;