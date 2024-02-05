package models

import "time"

type UserAuthEntity struct {
	UserID        int64     `db:"user_id"`
	UserUUID      string    `db:"user_uuid"`
	Email         string    `db:"email"`
	PasswordHash  string    `db:"password_hash"`
	EmailVerified bool      `db:"email_verified"`
	CreatedAt     time.Time `db:"created_at"`
}
