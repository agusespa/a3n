package models

import "time"

type UserAuthEntity struct {
	UserID        int64     `db:"user_id"`
	UserUUID      string    `db:"user_uuid"`
	Email         string    `db:"email"`
	PasswordHash  []byte    `db:"password_hash"`
	EmailVerified bool      `db:"email_verified"`
	CreatedAt     time.Time `db:"created_at"`
}

type TokenEntity struct {
	TokenID   int64      `db:"token_id"`
	TokenHash []byte     `db:"token_hash"`
	Revoked   bool       `db:"revoked"`
	UserID    int64      `db:"user_id"`
	CreatedAt time.Time  `db:"created_at"`
	ExpiresAt *time.Time `db:"expires_at"` // Pointer for nullable expires_at
}
