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
}

type UserAuthData struct {
	UserUUID     string `json:"userUUID"`
	Email        string `json:"email"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshRequestResponse struct {
	Token string `json:"token"`
}

type CustomClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type RegistrationResponse struct {
	UserID int64 `json:"userId"`
}

func NewUserAuthData(userUUID, email, accessToken, refreshToken string) UserAuthData {
	return UserAuthData{
		UserUUID:     userUUID,
		Email:        email,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
}
