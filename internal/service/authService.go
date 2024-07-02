package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/mail"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/logger"
	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/repository"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	email "github.com/sendgrid/sendgrid-go/helpers/mail"
)

type AuthService interface {
	PostUser(body models.UserRequest) (int64, error)
	BuildVerificationEmail(firstName, lastName, email string) (*email.SGMailV3, error)
	PutUserEmailVerification(email string) error
	PutUserEmail(username, password, newEmail string) (int64, error)
	PutUserPassword(username, password, newPassword string) (int64, error)
	GetUserLogin(username, password string) (models.UserAuthData, error)
	GetRefreshToken(refreshToken string) (string, error)
	DeleteToken(refreshToken string) error
	DeleteAllTokens(refreshToken string) error
	ValidateToken(token string) (*models.CustomClaims, error)
}

type UserAuthService struct {
	AuthRepo        repository.AuthRepository
	EncryptionKey   []byte
	RefreshTokenExp int
	AccessTokenExp  int
	EmailSrv        EmailService
	HardVerify      bool
	Logger          logger.Logger
}

func NewAuthService(authRepo *repository.UserAuthRepository, config models.ApiConfig, emailSrv EmailService, encryptionKey string, logger logger.Logger) *UserAuthService {
	return &UserAuthService{
		AuthRepo:        authRepo,
		EncryptionKey:   []byte(encryptionKey),
		RefreshTokenExp: config.Token.RefreshExp,
		AccessTokenExp:  config.Token.AccessExp,
		EmailSrv:        emailSrv,
		HardVerify:      config.Email.HardVerify,
		Logger:          logger}
}

func (as *UserAuthService) PostUser(body models.UserRequest) (int64, error) {
	if !isValidEmail(body.Email) {
		err := errors.New("not a valid email address")
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusBadRequest)
		return 0, err
	}
	if !isValidPassword(body.Password) {
		err := errors.New("password doesn't meet minimum criteria")
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusBadRequest)
		return 0, err
	}
	if body.FirstName == "" || body.LastName == "" {
		err := errors.New("name not provided")
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusBadRequest)
		return 0, err
	}

	uuidStr := uuid.New().String()

	hashedPassword, err := as.hashPassword(body.Password)
	if err != nil {
		return 0, err
	}

	id, err := as.AuthRepo.CreateUser(uuidStr, body, hashedPassword)
	if err != nil {
		as.Logger.LogError(err)
		return 0, err
	}

	go func() {
		verificationEmail, err := as.BuildVerificationEmail(body.FirstName, body.LastName, body.Email)
		if err == nil {
			as.EmailSrv.SendEmail(verificationEmail)
		}
	}()

	return id, nil
}

func (as *UserAuthService) BuildVerificationEmail(firstName, lastName, email string) (*email.SGMailV3, error) {
	token, err := as.generateEmailVerifyJWT(email)
	if err != nil {
		return nil, err
	}

	return as.EmailSrv.BuildVerificationEmail(firstName, lastName, email, token), nil
}

func (as *UserAuthService) PutUserEmailVerification(email string) error {
	err := as.AuthRepo.UpdateUserEmailVerification(email)
	if err != nil {
		as.Logger.LogError(err)
	}
	return err
}

func (as *UserAuthService) PutUserEmail(username, password, newEmail string) (int64, error) {
	if !isValidEmail(newEmail) {
		err := errors.New("not a valid email address")
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusBadRequest)
		return 0, err
	}

	userData, err := as.AuthRepo.ReadUserByEmail(username)
	if err != nil {
		as.Logger.LogError(err)
		return 0, err
	}

	if err := verifyHashedPassword(userData.PasswordHash, password); err != nil {
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return 0, err
	}

	id, err := as.AuthRepo.UpdateUserEmail(userData.UserID, newEmail)
	if err != nil {
		as.Logger.LogError(err)
		return 0, err
	}

	return id, nil
}

func (as *UserAuthService) PutUserPassword(username, password, newPassword string) (int64, error) {
	if !isValidPassword(newPassword) {
		err := errors.New("password doesn't meet minimum criteria")
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusBadRequest)
		return 0, err
	}

	userData, err := as.AuthRepo.ReadUserByEmail(username)
	if err != nil {
		as.Logger.LogError(err)
		return 0, err
	}

	if err := verifyHashedPassword(userData.PasswordHash, password); err != nil {
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return 0, err
	}

	hashedPassword, err := as.hashPassword(newPassword)
	if err != nil {
		return 0, err
	}

	id, err := as.AuthRepo.UpdateUserPassword(userData.UserID, &hashedPassword)
	if err != nil {
		as.Logger.LogError(err)
		return 0, err
	}

	return id, nil
}

func (as *UserAuthService) GetUserLogin(username, password string) (models.UserAuthData, error) {
	var userAuthData models.UserAuthData

	userData, err := as.AuthRepo.ReadUserByEmail(username)
	if err != nil {
		as.Logger.LogError(err)
		return userAuthData, err
	}

	if !userData.EmailVerified {
		go func() {
			verificationEmail, err := as.BuildVerificationEmail(userData.FirstName, userData.LastName, userData.Email)
			if err == nil {
				as.EmailSrv.SendEmail(verificationEmail)
			}
		}()
		if as.HardVerify {
			err := errors.New("email verification required")
			as.Logger.LogError(err)
			err = httperrors.NewError(err, http.StatusForbidden)
			return userAuthData, err
		}
	}

	if err := verifyHashedPassword(userData.PasswordHash, password); err != nil {
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return userAuthData, err
	}

	refreshToken, err := as.generateRefreshToken()
	if err != nil {
		return userAuthData, err
	}

	refreshTokenHash, err := as.hashRefreshToken(refreshToken)
	if err != nil {
		return userAuthData, err
	}
	if err := as.AuthRepo.CreateRefreshToken(userData.UserID, refreshTokenHash); err != nil {
		as.Logger.LogError(err)
		return userAuthData, err
	}

	accessToken, err := as.generateAccessJWT(userData.UserID, userData.UserUUID)
	if err != nil {
		return userAuthData, err
	}

	userAuthData = models.NewUserAuthData(userData.UserID, userData.EmailVerified, userData.UserUUID, accessToken, refreshToken)
	return userAuthData, err
}

func (as *UserAuthService) GetRefreshToken(refreshToken string) (string, error) {

	refreshTokenHash, err := as.hashRefreshToken(refreshToken)
	if err != nil {
		return "", err
	}
	userData, err := as.AuthRepo.ReadUserByToken(refreshTokenHash)
	if err != nil {
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return "", err
	}

	accessToken, err := as.generateAccessJWT(userData.UserID, userData.UserUUID)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (as *UserAuthService) DeleteToken(refreshToken string) error {
	refreshTokenHash, err := as.hashRefreshToken(refreshToken)
	if err != nil {
		return err
	}
	if err := as.AuthRepo.DeleteTokenByHash(refreshTokenHash); err != nil {
		as.Logger.LogError(err)
		return err
	}

	return nil
}

func (as *UserAuthService) DeleteAllTokens(refreshToken string) error {
	refreshTokenHash, err := as.hashRefreshToken(refreshToken)
	if err != nil {
		return err
	}
	userData, err := as.AuthRepo.ReadUserByToken(refreshTokenHash)
	if err != nil {
		as.Logger.LogError(err)
		return err
	}
	if err := as.AuthRepo.DeleteAllTokensByUserId(userData.UserID); err != nil {
		as.Logger.LogError(err)
		return err
	}

	return nil
}

func (as *UserAuthService) ValidateToken(token string) (*models.CustomClaims, error) {
	parsedToken, err := jwt.ParseWithClaims(
		token,
		&models.CustomClaims{},
		func(token *jwt.Token) (any, error) {
			return as.EncryptionKey, nil
		},
	)
	if err != nil {
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return &models.CustomClaims{}, err
	}

	claims, ok := parsedToken.Claims.(*models.CustomClaims)
	if !ok {
		err := errors.New("failed to parse token claims")
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return &models.CustomClaims{}, err
	}

	return claims, nil
}

func (as *UserAuthService) hashPassword(password string) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return nil, err
	}

	return hashedPassword, nil
}

func (as *UserAuthService) generateAccessJWT(userID int64, userUUID string) (string, error) {
	accessExpiresBy := time.Now().Add(time.Duration(as.AccessTokenExp) * time.Minute).Unix()
	claims := models.CustomClaims{
		User: models.TokenUser{
			UserID:   userID,
			UserUUID: userUUID},
		Type: "access",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: accessExpiresBy,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(as.EncryptionKey)
	if err != nil {
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return "", err
	}

	return tokenString, nil
}

func (as *UserAuthService) generateRefreshToken() (string, error) {
	token := make([]byte, 96)
	_, err := rand.Read(token)
	if err != nil {
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return "", err
	}

	encodedToken := base64.StdEncoding.EncodeToString(token)
	return encodedToken, nil
}

func (as *UserAuthService) hashRefreshToken(token string) ([]byte, error) {
	decodedToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return nil, err
	}

	hasher := sha256.New()
	hasher.Write(decodedToken)
	hashedToken := hasher.Sum(nil)
	return hashedToken, nil
}

func (as *UserAuthService) generateEmailVerifyJWT(email string) (string, error) {
	expiration := time.Now().Add(60 * time.Minute).Unix()
	claims := models.CustomClaims{
		Email: email,
		Type:  "email_verify",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(as.EncryptionKey)
	if err != nil {
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return "", err
	}

	return tokenString, nil
}

func verifyHashedPassword(hashedPassword []byte, password string) error {
	err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	return err
}

func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func isValidPassword(password string) bool {
	regexPattern := `^.{8,}$`
	match, _ := regexp.MatchString(regexPattern, password)
	return match
}
