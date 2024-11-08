package models

import (
	"database/sql"
	"time"
)

type RealmEntity struct {
	RealmID       int64          `db:"realm_id"`
	RealmName     string         `db:"realm_name"`
	RealmDomain   string         `db:"realm_domain"`
	RefreshExp    int64          `db:"refresh_exp"`
	AccessExp     int64          `db:"access_exp"`
	EmailVerify   bool           `db:"email_verify"`
	EmailProvider sql.NullString `db:"email_provider"`
	EmailSender   sql.NullString `db:"email_sender"`
	EmailAddr     sql.NullString `db:"email_addr"`
	ApiKey        sql.NullString `db:"api_key"`
}

type UserAuthEntity struct {
	UserID        int64          `db:"user_id"`
	UserUUID      string         `db:"user_uuid"`
	FirstName     string         `db:"first_name"`
	MiddleName    sql.NullString `db:"middle_name"`
	LastName      string         `db:"last_name"`
	Email         string         `db:"email"`
	Role          string         `db:"role"`
	PasswordHash  []byte         `db:"password_hash"`
	EmailVerified bool           `db:"email_verified"`
	CreatedAt     time.Time      `db:"created_at"`
	Roles         sql.NullString `db:"roles"`
}

type TokenEntity struct {
	TokenID   int64        `db:"token_id"`
	TokenHash []byte       `db:"token_hash"`
	Revoked   bool         `db:"revoked"`
	UserID    int64        `db:"user_id"`
	CreatedAt time.Time    `db:"created_at"`
	ExpiresAt sql.NullTime `db:"expires_at"`
}

type RoleEntity struct {
	RoleID   int64  `db:"role_id"`
	RoleName string `db:"role_name"`
}
