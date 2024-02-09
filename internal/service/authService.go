package service

import (
	"errors"
	"net/http"
	"os"
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

	var refreshToken string
	if userData.RefreshToken != "" {
		refreshToken = userData.RefreshToken
	} else {
		newToken, err := generateRefreshJWT(userData.UserID, userData.UserUUID)
		if err != nil {
			return userAuthData, err
		}

		refreshToken = newToken
		if err := as.AuthRepo.UpdateRefreshToken(userData.UserID, &refreshToken); err != nil {
			return userAuthData, err
		}
	}

	accessExpiresBy := time.Now().Add(5 * time.Minute).Unix()
	accessToken, err := generateAccessJWT(userData.UserID, userData.UserUUID, accessExpiresBy)
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

	if claims.Type != "refresh" {
		err := httperrors.NewError(nil, http.StatusUnauthorized)
		return "", err
	}

	userData, err := as.AuthRepo.QueryUserById(claims.User.UserID)
	if err != nil {
		return "", err
	}

	if userData.RefreshToken != refreshToken {
		err := httperrors.NewError(err, http.StatusUnauthorized)
		return "", err
	}

	accessExpiresBy := time.Now().Add(5 * time.Minute).Unix()
	accessToken, err := generateAccessJWT(claims.User.UserID, claims.User.UserUUID, accessExpiresBy)
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

	if claims.Type != "refresh" {
		err := httperrors.NewError(nil, http.StatusUnauthorized)
		return err
	}

	if err := as.AuthRepo.UpdateRefreshToken(claims.User.UserID, nil); err != nil {
		return err
	}

	return nil
}

func (as *AuthService) ValidateToken(refreshToken string) (*models.CustomClaims, error) {
	key, err := getEncryptionKey()
	if err != nil {
		return nil, err
	}
	parsedToken, err := jwt.ParseWithClaims(
		refreshToken,
		&models.CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return key, nil
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

func generateAccessJWT(userID int64, userUUID string, expiration int64) (string, error) {
	claims := models.CustomClaims{
		User: models.TokenUser{
			UserID:   userID,
			UserUUID: userUUID},
		Type: "access",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	key, err := getEncryptionKey()
	if err != nil {
		return "", err
	}
	tokenString, err := token.SignedString(key)
	if err != nil {
		err := httperrors.NewError(err, http.StatusInternalServerError)
		return "", err
	}

	return tokenString, nil
}

func generateRefreshJWT(userID int64, userUUID string) (string, error) {
	tokenUUID := uuid.New().String()
	claims := models.CustomClaims{
		User: models.TokenUser{
			UserID:   userID,
			UserUUID: userUUID},
		Type: "refresh",
		StandardClaims: jwt.StandardClaims{
			Id: tokenUUID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	key, err := getEncryptionKey()
	if err != nil {
		return "", err
	}
	tokenString, err := token.SignedString(key)
	if err != nil {
		err := httperrors.NewError(err, http.StatusInternalServerError)
		return "", err
	}

	return tokenString, nil
}

func getEncryptionKey() ([]byte, error) {
	keyString := os.Getenv("ENCRYPTION_KEY")
	if keyString == "" {
		err := httperrors.NewError(nil, http.StatusInternalServerError)
		return nil, err
	}
	return []byte(keyString), nil
}
