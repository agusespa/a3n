package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/slices"

	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/logger"
	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/repository"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	email "github.com/sendgrid/sendgrid-go/helpers/mail"
)

type ApiService interface {
	PostUser(body models.UserRequest) (int64, error)
	BuildVerificationEmail(firstName, lastName, email string) (*email.SGMailV3, error)
	PutUserEmailVerification(email string) error
	PutUserEmail(username, password, newEmail string) (int64, error)
	PutUserPassword(username, password, newPassword string) (int64, error)
	GetUserData(id int64) (models.UserData, error)
	GetUserLogin(username, password string) (models.UserAuthData, error)
	GetUserAdminLogin(username, password, ipAddr string) (models.UserAuthData, error)
	GetFreshAccessToken(refreshToken string) (string, int64, error)
	DeleteToken(refreshToken string) error
	DeleteAllTokens(refreshToken string) error
	ValidateToken(token string) (*models.CustomClaims, error)
	BuildCookie(name, value string, options models.CookieOptions) *http.Cookie
}

type DefaultApiService struct {
	AuthRepo        repository.AuthRepository
	EncryptionKey   []byte
	RefreshTokenExp int
	AccessTokenExp  int
	EmailSrv        EmailService
	HardVerify      bool
	Domain          string
	Logger          logger.Logger
}

func NewDefaultApiService(authRepo *repository.MySqlRepository, config models.ApiConfig, emailSrv EmailService, encryptionKey string, logger logger.Logger) *DefaultApiService {
	var refreshExp int
	if config.Token.RefreshExp == 0 {
		refreshExp = 525600 // defaults to a year
	} else {
		refreshExp = config.Token.RefreshExp
	}

	var accessExp int
	if config.Token.AccessExp == 0 {
		accessExp = 5 // default to 5 minutes
	} else {
		accessExp = config.Token.AccessExp
	}

	return &DefaultApiService{
		AuthRepo:        authRepo,
		EncryptionKey:   []byte(encryptionKey),
		RefreshTokenExp: refreshExp,
		AccessTokenExp:  accessExp,
		EmailSrv:        emailSrv,
		HardVerify:      config.Email.HardVerify,
		Domain:          config.Client.Domain,
		Logger:          logger}
}

func (as *DefaultApiService) PostUser(body models.UserRequest) (int64, error) {
	if !IsValidEmail(body.Email) {
		err := errors.New("not a valid email address")
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusBadRequest)
		return 0, err
	}
	if !IsValidPassword(body.Password) {
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

func (as *DefaultApiService) BuildVerificationEmail(firstName, lastName, email string) (*email.SGMailV3, error) {
	token, err := as.generateEmailVerifyJWT(email)
	if err != nil {
		return nil, err
	}

	return as.EmailSrv.BuildVerificationEmail(firstName, lastName, email, token), nil
}

func (as *DefaultApiService) PutUserEmailVerification(email string) error {
	err := as.AuthRepo.UpdateUserEmailVerification(email)
	if err != nil {
		as.Logger.LogError(err)
	}
	return err
}

func (as *DefaultApiService) PutUserEmail(username, password, newEmail string) (int64, error) {
	if !IsValidEmail(newEmail) {
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

func (as *DefaultApiService) PutUserPassword(username, password, newPassword string) (int64, error) {
	if !IsValidPassword(newPassword) {
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

func (as *DefaultApiService) GetUserLogin(username, password string) (models.UserAuthData, error) {
	var userAuthData models.UserAuthData

	userEntity, err := as.AuthRepo.ReadUserByEmail(username)
	if err != nil {
		as.Logger.LogError(err)
		return userAuthData, err
	}

	if !userEntity.EmailVerified {
		go func() {
			verificationEmail, err := as.BuildVerificationEmail(userEntity.FirstName, userEntity.LastName, userEntity.Email)
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

	if err := verifyHashedPassword(userEntity.PasswordHash, password); err != nil {
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
	if err := as.AuthRepo.CreateRefreshToken(userEntity.UserID, refreshTokenHash); err != nil {
		as.Logger.LogError(err)
		return userAuthData, err
	}

	roles := []string{}
	if userEntity.Roles.Valid {
		roles = strings.Split(userEntity.Roles.String, ",")
	}

	accessToken, err := as.generateAccessJWT(userEntity.UserID, userEntity.UserUUID, roles)
	if err != nil {
		return userAuthData, err
	}

	userAuthData = models.NewUserAuthData(userEntity.UserID, userEntity.EmailVerified, userEntity.UserUUID, accessToken, refreshToken)
	return userAuthData, err
}

func (as *DefaultApiService) GetUserAdminLogin(username, password, ipAddr string) (models.UserAuthData, error) {
	var userAuthData models.UserAuthData

	userEntity, err := as.AuthRepo.ReadUserByEmail(username)
	if err != nil {
		as.Logger.LogError(err)
		return userAuthData, err
	}

	if err := verifyHashedPassword(userEntity.PasswordHash, password); err != nil {
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return userAuthData, err
	}

	roles := []string{}
	if userEntity.Roles.Valid {
		roles = strings.Split(userEntity.Roles.String, ",")
	}
	if !slices.Contains(roles, "admin") {
		err = httperrors.NewError(errors.New("missing admin role"), http.StatusForbidden)
		as.Logger.LogError(err)
		return userAuthData, err
	}

	accessToken, err := as.generateAdminSessionJWT(userEntity.UserID, userEntity.UserUUID, roles, ipAddr)
	if err != nil {
		return userAuthData, err
	}

	userAuthData = models.NewUserAuthData(userEntity.UserID, userEntity.EmailVerified, userEntity.UserUUID, accessToken, "")
	return userAuthData, err
}

func (as *DefaultApiService) GetUserData(id int64) (models.UserData, error) {
	var userData models.UserData

	userEntity, err := as.AuthRepo.ReadUserById(id)
	if err != nil {
		as.Logger.LogError(err)
		return userData, err
	}

	roles := []string{}
	if userEntity.Roles.Valid {
		roles = strings.Split(userEntity.Roles.String, ",")
	}

	userData = models.NewUserData(userEntity.UserID, userEntity.EmailVerified, userEntity.UserUUID, userEntity.Email, userEntity.FirstName, userEntity.LastName, userEntity.MiddleName, userEntity.CreatedAt, roles)
	return userData, err
}

func (as *DefaultApiService) GetFreshAccessToken(refreshToken string) (string, int64, error) {

	refreshTokenHash, err := as.hashRefreshToken(refreshToken)
	if err != nil {
		return "", -1, err
	}
	userEntity, err := as.AuthRepo.ReadUserByToken(refreshTokenHash)
	if err != nil {
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return "", -1, err
	}

	roles := []string{}
	if userEntity.Roles.Valid {
		roles = strings.Split(userEntity.Roles.String, ",")
	}

	accessToken, err := as.generateAccessJWT(userEntity.UserID, userEntity.UserUUID, roles)
	if err != nil {
		return "", -1, err
	}

	return accessToken, userEntity.UserID, nil
}

func (as *DefaultApiService) DeleteToken(refreshToken string) error {
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

func (as *DefaultApiService) DeleteAllTokens(refreshToken string) error {
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

func (as *DefaultApiService) ValidateToken(token string) (*models.CustomClaims, error) {
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

func (as *DefaultApiService) hashPassword(password string) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		as.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return nil, err
	}

	return hashedPassword, nil
}

func (as *DefaultApiService) generateAccessJWT(userID int64, userUUID string, roles []string) (string, error) {
	accessExpiresBy := time.Now().Add(time.Duration(as.AccessTokenExp) * time.Minute).Unix()
	claims := models.CustomClaims{
		User: models.TokenUser{
			UserID:   userID,
			UserUUID: userUUID},
		Type:  "access",
		Roles: roles,
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

func (as *DefaultApiService) generateAdminSessionJWT(userID int64, userUUID string, roles []string, ipAddr string) (string, error) {
	accessExpiresBy := time.Now().Add(time.Duration(10) * time.Minute).Unix()
	claims := models.CustomClaims{
		User: models.TokenUser{
			UserID:   userID,
			UserUUID: userUUID},
		Type:   "admin",
		Roles:  roles,
		IpAddr: ipAddr,
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

func (as *DefaultApiService) generateRefreshToken() (string, error) {
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

func (as *DefaultApiService) hashRefreshToken(token string) ([]byte, error) {
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

func (as *DefaultApiService) generateEmailVerifyJWT(email string) (string, error) {
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

func IsValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func IsValidPassword(password string) bool {
	regexPattern := `^.{8,}$`
	match, _ := regexp.MatchString(regexPattern, password)
	return match
}

func (as *DefaultApiService) BuildCookie(name, value string, options models.CookieOptions) *http.Cookie {
	cookie := http.Cookie{
		Name:     name,
		Value:    base64.URLEncoding.EncodeToString([]byte(value)),
		Path:     options.Path,
		HttpOnly: true,
	}

	switch options.Expiration {
	case models.Access:
		expiresBy := time.Now().Add(time.Duration(as.AccessTokenExp) * time.Minute)
		cookie.Expires = expiresBy
	case models.Refresh:
		expiresBy := time.Now().Add(time.Duration(as.RefreshTokenExp) * time.Minute)
		cookie.Expires = expiresBy
	}
	return &cookie
}
