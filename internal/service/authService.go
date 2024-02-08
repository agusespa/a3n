package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/agusespa/autz/internal/httperrors"
	"github.com/agusespa/autz/internal/models"
	"github.com/agusespa/autz/internal/repository"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type AuthService struct {
	AuthRepo *repository.AuthRepository
}

func NewProductService(authRepo *repository.AuthRepository) *AuthService {
	return &AuthService{AuthRepo: authRepo}
}

func (as *AuthService) RegisterNewUser(body models.AuthRequest) (int64, error) {
	uuidStr := uuid.New().String()

	hashedPassword, err := hashPassword(body.Password)
	if err != nil {
		err := httperrors.NewError(err, http.StatusInternalServerError)
		return 0, err
	}

	id, err := as.AuthRepo.CreateUser(uuidStr, body.Email, hashedPassword)
	return id, err
}

func (as *AuthService) LoginUser(username, password string) (models.UserAuthData, error) {
	var userAuthData models.UserAuthData

	userData, err := as.AuthRepo.QueryUserByEmail(username)
	if err != nil {
		return userAuthData, err
	}

	if err := verifyHashedPassword(userData.PasswordHash, password); err != nil {
		err := httperrors.NewError(err, http.StatusUnauthorized)
		return userAuthData, err
	}

	refreshToken, err := generateJWT(userData.UserID, userData.UserUUID, 0)
	if err != nil {
		return userAuthData, err
	}

	hashedToken, err := hashToken(refreshToken)
	if err != nil {
		err := httperrors.NewError(err, http.StatusInternalServerError)
		return userAuthData, err
	}
	if err := as.AuthRepo.UpdateRefreshToken(userData.UserID, &hashedToken); err != nil {
		return userAuthData, err
	}

	accessExpiresBy := time.Now().Add(5 * time.Minute).Unix()
	accessToken, err := generateJWT(userData.UserID, userData.UserUUID, accessExpiresBy)
	if err != nil {
		return userAuthData, err
	}

	userAuthData = models.NewUserAuthData(userData.UserID, userData.UserUUID, accessToken, refreshToken)
	return userAuthData, err
}

func (as *AuthService) RefreshToken(refreshToken string) (string, error) {
	claims, err := as.ValidateToken(refreshToken)
	if err != nil {
		return "", err
	}

	userData, err := as.AuthRepo.QueryUserById(claims.UserID)
	if err != nil {
		return "", err
	}

	if err := verifyHashedToken(userData.RefreshToken, refreshToken); err != nil {
		err := httperrors.NewError(err, http.StatusUnauthorized)
		return "", err
	}

	accessExpiresBy := time.Now().Add(5 * time.Minute).Unix()
	accessToken, err := generateJWT(claims.UserID, claims.UserUUID, accessExpiresBy)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (as *AuthService) RevoqueToken(refreshToken string) error {
	claims, err := as.ValidateToken(refreshToken)
	if err != nil {
		return err
	}

	if err := as.AuthRepo.UpdateRefreshToken(claims.UserID, nil); err != nil {
		return err
	}

	return nil
}

func (as *AuthService) ValidateToken(refreshToken string) (*models.CustomClaims, error) {
	parsedToken, err := jwt.ParseWithClaims(
		refreshToken,
		&models.CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return privateKey, nil
		},
	)
	if err != nil {
		err := httperrors.NewError(err, http.StatusUnauthorized)
		return &models.CustomClaims{}, err
	}

	claims, ok := parsedToken.Claims.(*models.CustomClaims)
	if !ok {
		err := httperrors.NewError(errors.New("failed to parse token claims"), http.StatusUnauthorized)
		return &models.CustomClaims{}, err
	}

	return claims, nil
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

func verifyHashedPassword(hashedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err
}

func hashToken(token string) (string, error) {
	hasher := sha256.New()

	_, err := hasher.Write([]byte(token))
	if err != nil {
		return "", err
	}

	hashedTokenBytes := hasher.Sum(nil)
	hashedToken := hex.EncodeToString(hashedTokenBytes)

	return hashedToken, nil
}

func verifyHashedToken(storedToken, clientToken string) error {
	hashedClientToken, err := hashToken(clientToken)
	if err != nil {
		return err
	}

	if hashedClientToken != storedToken {
		return errors.New("token doesn't match original")
	}

	return nil
}

func generateJWT(userID int64, userUUID string, expiration int64) (string, error) {
	claims := models.CustomClaims{
		UserID:   userID,
		UserUUID: userUUID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration,
			// TODO: use environment variable
			Issuer: "ecom",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		err := httperrors.NewError(err, http.StatusInternalServerError)
		return "", err
	}

	return tokenString, nil
}

var privateKey = []byte("AAAAB3NzaC1yc2EAAAADAQABAAABgQDVWRMI4ex2hUf0Lz/lPhbxIq3m28agw4XTOzYE2BwbHOlrAs23+rRyAW0jlaS1dCRz09fUGAqlxV13sQinS/VACXzvKzdCOxxGno2hGuIbxH6baXVmDRbFlK9qdeMtzXnppZ4cIVq33Y1IJYwZ1erj6QYqPhHcl4FmYuOL76/A6RptF3njBFqfU241lZuuDnbe2cFeihj0TFUOQVoH0Y/JK+Gwy0pebNy8hjnyGQZNBVeZw9R5UMxphtb2pbL1lKCoM7MDPLKGN+hhjRZyeLYEy/8AR1xiwE+R7LDaG/Zik5xQJ/YXYXMQBN2Ip4dTZdn40iuk+IWmaNT92Q5CpPvZO0aU5LWxPSLlZot4IloQZXr11ZKUXxzZvAh7OQXbolN/qTdBtKeOjw7iKvKiKGXTw6Uoq8fEUglPhX6ZcdGmELpHMx8VliXUjNPXbm9mSPk6Izx+HkcK2Zg5JLoqGNXf3wcOfbeJvEAAPafPlKFqoL/Okxgn/+fXuCh//z5Hrf0=")
