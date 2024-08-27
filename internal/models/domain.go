package models

import (
	"database/sql"
	"time"

	"github.com/golang-jwt/jwt"
)

type User struct {
	UserID        int64     `json:"userID"`
	UserUUID      string    `json:"userUUID"`
	FirstName     string    `json:"firstName"`
	MiddleName    string    `json:"middleName"`
	LastName      string    `json:"lastName"`
	Email         string    `json:"email"`
	PasswordHash  []byte    `json:"passwordHash"`
	EmailVerified bool      `json:"emailVerified"`
	CreatedAt     time.Time `json:"createdAt"`
	RefreshToken  string    `json:"refreshToken"`
}

type UserRequest struct {
	FirstName  string `json:"firstName"`
	MiddleName string `json:"middleName"`
	LastName   string `json:"lastName"`
	Email      string `json:"email"`
	Password   string `json:"password"`
}

type RefreshToken struct {
	TokenID   int64      `json:"tokenID"`
	TokenHash []byte     `json:"tokenHash"`
	Revoked   bool       `json:"revoked"`
	UserID    int64      `json:"userID"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt *time.Time `json:"expiresAt"`
}

type UserAuthData struct {
	UserID        int64  `json:"user_id"`
	UserUUID      string `json:"userUUID"`
	EmailVerified bool   `json:"emailVerified"`
	AccessToken   string `json:"accessToken"`
	RefreshToken  string `json:"refreshToken"`
}

type UserData struct {
	UserID        int64     `json:"userID"`
	UserUUID      string    `json:"userUUID"`
	FirstName     string    `json:"firstName"`
	MiddleName    string    `json:"middleName"`
	LastName      string    `json:"lastName"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"emailVerified"`
	CreatedAt     time.Time `json:"createdAt"`
}

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshRequestResponse struct {
	UserID      int64  `json:"user_id"`
	AccessToken string `json:"accessToken"`
}

type CustomClaims struct {
	User  TokenUser `json:"user"`
	Email string    `json:"email"`
	Type  string    `json:"type"`
	jwt.StandardClaims
}

type TokenUser struct {
	UserID   int64  `json:"userID"`
	UserUUID string `json:"userUUID"`
}

type RegistrationResponse struct {
	UserID int64 `json:"userID"`
}

type AuthenticationResponse struct {
	UserUUID string `json:"userUUID"`
}

type CookieExpKind string

const (
	Access  CookieExpKind = "access"
	Refresh CookieExpKind = "refresh"
	Session CookieExpKind = "session"
)

type CookieOptions struct {
	Path       string
	Expiration CookieExpKind
}

func NewUserAuthData(userID int64, emailVerified bool, userUUID, accessToken, refreshToken string) UserAuthData {
	return UserAuthData{
		UserID:        userID,
		UserUUID:      userUUID,
		EmailVerified: emailVerified,
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
	}
}

func NewUserData(userID int64, emailVerified bool, userUUID, firstName, lastName, email string, middleNameNullStr sql.NullString, createdAt time.Time) UserData {
	return UserData{
		UserID:        userID,
		UserUUID:      userUUID,
		FirstName:     firstName,
		MiddleName:    middleNameNullStr.String,
		LastName:      lastName,
		Email:         email,
		EmailVerified: emailVerified,
		CreatedAt:     createdAt,
	}
}
