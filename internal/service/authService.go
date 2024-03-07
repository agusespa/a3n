package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

func (as *AuthService) EditUserData(userID int64, body models.AuthRequest) (int64, error) {
	var hashedPassword []byte
	if body.Password != "" {
		var err error
		hashedPassword, err = hashPassword(body.Password)
		if err != nil {
			err := httperrors.NewError(err, http.StatusInternalServerError)
			return 0, err
		}
	}

	id, err := as.AuthRepo.UpdateUser(userID, body.Email, &hashedPassword)
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

	refreshToken, err := generateRefreshToken()
	if err != nil {
		return userAuthData, err
	}

	refreshTokenHash, err := hashRefreshToken(refreshToken)
	if err != nil {
		return userAuthData, err
	}
	if err := as.AuthRepo.CreateRefreshToken(userData.UserID, refreshTokenHash); err != nil {
		return userAuthData, err
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

	refreshTokenHash, err := hashRefreshToken(refreshToken)
	if err != nil {
		return "", err
	}
	userData, err := as.AuthRepo.QueryUserByToken(refreshTokenHash)
	if err != nil {
		err := httperrors.NewError(err, http.StatusUnauthorized)
		return "", err
	}

	accessExpiresBy := time.Now().Add(5 * time.Minute).Unix()
	accessToken, err := generateAccessJWT(userData.UserID, userData.UserUUID, accessExpiresBy)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (as *AuthService) RevoqueToken(refreshToken string) error {
	refreshTokenHash, err := hashRefreshToken(refreshToken)
	if err != nil {
		return err
	}
	if err := as.AuthRepo.DeleteTokenByHash(refreshTokenHash); err != nil {
		return err
	}

	return nil
}

func (as *AuthService) RevoqueUserTokens(refreshToken string) error {
	refreshTokenHash, err := hashRefreshToken(refreshToken)
	if err != nil {
		return err
	}
	userData, err := as.AuthRepo.QueryUserByToken(refreshTokenHash)
	if err != nil {
		err := httperrors.NewError(err, http.StatusUnauthorized)
		return err
	}
	if err := as.AuthRepo.DeleteUserTokensById(userData.UserID); err != nil {
		return err
	}

	return nil
}

func (as *AuthService) ValidateToken(token string) (*models.CustomClaims, error) {
	key, err := getEncryptionKey()
	if err != nil {
		return nil, err
	}
	parsedToken, err := jwt.ParseWithClaims(
		token,
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

func hashPassword(password string) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return hashedPassword, nil
}

func verifyHashedPassword(hashedPassword []byte, password string) error {
	err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
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

func generateRefreshToken() (string, error) {
	token := make([]byte, 96)
	_, err := rand.Read(token)
	if err != nil {
		err := httperrors.NewError(err, http.StatusInternalServerError)
		return "", err
	}

	encodedToken := base64.StdEncoding.EncodeToString(token)
	return encodedToken, nil
}

func hashRefreshToken(token string) ([]byte, error) {
	decodedToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		err := httperrors.NewError(err, http.StatusInternalServerError)
		return nil, err
	}

	hasher := sha256.New()
	hasher.Write(decodedToken)
	hashedToken := hasher.Sum(nil)
	return hashedToken, nil
}

func getEncryptionKey() ([]byte, error) {
	keyString := os.Getenv("ENCRYPTION_KEY")
	if keyString == "" {
		err := httperrors.NewError(nil, http.StatusInternalServerError)
		return nil, err
	}
	return []byte(keyString), nil
}
