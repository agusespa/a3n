package models

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type UserAuth struct {
	UserID        int64     `json:"user_id"`
	UserUUID      string    `json:"userUUID"`
	Email         string    `json:"email"`
	PasswordHash  string    `json:"passwordHash"`
	EmailVerified bool      `json:"emailVerified"`
	CreatedAt     time.Time `json:"createdAt"`
	RefreshToken  string    `json:"refreshToken"`
}

type UserAuthData struct {
	UserID       int64  `json:"user_id"`
	UserUUID     string `json:"userUUID"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshRequestResponse struct {
	AccessToken string `json:"accessToken"`
}

type CustomClaims struct {
	User TokenUser `json:"user"`
	Type string    `json:"type"`
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

func NewUserAuthData(userID int64, userUUID, accessToken, refreshToken string) UserAuthData {
	return UserAuthData{
		UserID:       userID,
		UserUUID:     userUUID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
}
