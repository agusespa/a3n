package models

import (
	"database/sql"
	"time"
)

type UserAuthEntity struct {
	UserID        int64          `db:"user_id"`
	UserUUID      string         `db:"user_uuid"`
	FirstName     string         `db:"first_name"`
	MiddleName    sql.NullString `db:"middle_name"`
	LastName      string         `db:"last_name"`
	Email         string         `db:"email"`
	PasswordHash  []byte         `db:"password_hash"`
	EmailVerified bool           `db:"email_verified"`
	CreatedAt     time.Time      `db:"created_at"`
}

type TokenEntity struct {
	TokenID   int64        `db:"token_id"`
	TokenHash []byte       `db:"token_hash"`
	Revoked   bool         `db:"revoked"`
	UserID    int64        `db:"user_id"`
	CreatedAt time.Time    `db:"created_at"`
	ExpiresAt sql.NullTime `db:"expires_at"`
}
