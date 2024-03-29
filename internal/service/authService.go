package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"net/mail"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/repository"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	email "github.com/sendgrid/sendgrid-go/helpers/mail"
)

type AuthService struct {
	AuthRepo        *repository.AuthRepository
	EncryptionKey   []byte
	RefreshTokenExp int
	AccessTokenExp  int
	EmailSrv        *EmailService
	ClientDomain    string
	HardVerify      bool
}

func NewAuthService(authRepo *repository.AuthRepository, config models.Config, emailSrv *EmailService, encryptionKey string) *AuthService {
	return &AuthService{AuthRepo: authRepo, EncryptionKey: []byte(encryptionKey), RefreshTokenExp: config.Token.RefreshExp, AccessTokenExp: config.Token.AccessExp, EmailSrv: emailSrv, ClientDomain: config.Client.Domain, HardVerify: config.Email.HardVerify}
}

func (as *AuthService) RegisterNewUser(body models.UserRequest) (int64, error) {
	if !isValidEmail(body.Email) {
		err := httperrors.NewError(errors.New("not a valid email address"), http.StatusBadRequest)
		return 0, err
	}
	if !isValidPassword(body.Password) {
		err := httperrors.NewError(errors.New("password doesn't meet minimum criteria"), http.StatusBadRequest)
		return 0, err
	}
	if body.FirstName == "" || body.LastName == "" {
		err := httperrors.NewError(errors.New("name not provided"), http.StatusBadRequest)
		return 0, err
	}

	uuidStr := uuid.New().String()

	hashedPassword, err := hashPassword(body.Password)
	if err != nil {
		err := httperrors.NewError(err, http.StatusInternalServerError)
		return 0, err
	}

	id, err := as.AuthRepo.CreateUser(uuidStr, body, hashedPassword)
	if err != nil {
		return 0, err
	}

	go func() {
		verificationEmail, err := as.BuildVerificationEmail(body.FirstName, body.LastName, body.Email)
		if err != nil {
			log.Printf("error: %v", err.Error())
		} else {
			as.EmailSrv.SendEmail(verificationEmail)
		}
	}()

	return id, nil
}

func (as *AuthService) BuildVerificationEmail(firstName, lastName, email string) (*email.SGMailV3, error) {
	fullName := firstName + " " + lastName
	subject := "Verify address"

	token, err := as.generateEmailVerifyJWT(email)
	if err != nil {
		err := httperrors.NewError(err, http.StatusInternalServerError)
		return nil, err
	}

	link := as.ClientDomain + "/verify/" + token
	message := "Follow this link to verify your email address: " + link
	template := "<p>Follow this link to verify your email address:&nbsp;</p><a>" + link + "</a>"

	return as.EmailSrv.BuildEmail(fullName, email, subject, message, template), nil
}

func (as *AuthService) EditUserEmailVerification(email string) error {
	err := as.AuthRepo.UpdateUserEmailVerification(email)
	return err
}

func (as *AuthService) EditUserEmail(username, password, newEmail string) (int64, error) {
	if !isValidEmail(newEmail) {
		err := httperrors.NewError(errors.New("not a valid email address"), http.StatusBadRequest)
		return 0, err
	}

	userData, err := as.AuthRepo.QueryUserByEmail(username)
	if err != nil {
		return 0, err
	}

	if err := verifyHashedPassword(userData.PasswordHash, password); err != nil {
		err := httperrors.NewError(err, http.StatusUnauthorized)
		return 0, err
	}

	id, err := as.AuthRepo.UpdateUserEmail(userData.UserID, newEmail)
	return id, err
}

func (as *AuthService) EditUserPassword(username, password, newPassword string) (int64, error) {
	if !isValidPassword(newPassword) {
		err := httperrors.NewError(errors.New("password doesn't meet minimum criteria"), http.StatusBadRequest)
		return 0, err
	}

	userData, err := as.AuthRepo.QueryUserByEmail(username)
	if err != nil {
		return 0, err
	}

	if err := verifyHashedPassword(userData.PasswordHash, password); err != nil {
		err := httperrors.NewError(err, http.StatusUnauthorized)
		return 0, err
	}

	hashedPassword, err := hashPassword(newPassword)
	if err != nil {
		err := httperrors.NewError(err, http.StatusInternalServerError)
		return 0, err
	}

	id, err := as.AuthRepo.UpdateUserPassword(userData.UserID, &hashedPassword)
	return id, err
}

func (as *AuthService) LoginUser(username, password string) (models.UserAuthData, error) {
	var userAuthData models.UserAuthData

	userData, err := as.AuthRepo.QueryUserByEmail(username)
	if err != nil {
		return userAuthData, err
	}

	if !userData.EmailVerified {
		go func() {
			verificationEmail, err := as.BuildVerificationEmail(userData.FirstName, userData.LastName, userData.Email)
			if err != nil {
				log.Printf("error: %v", err.Error())
			} else {
				as.EmailSrv.SendEmail(verificationEmail)
			}
		}()
		if as.HardVerify {
			customError := errors.New("email verification required")
			err := httperrors.NewError(customError, http.StatusForbidden)
			return userAuthData, err
		}
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

	accessToken, err := as.generateAccessJWT(userData.UserID, userData.UserUUID)
	if err != nil {
		return userAuthData, err
	}

	userAuthData = models.NewUserAuthData(userData.UserID, userData.EmailVerified, userData.UserUUID, accessToken, refreshToken)
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

	accessToken, err := as.generateAccessJWT(userData.UserID, userData.UserUUID)
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
	parsedToken, err := jwt.ParseWithClaims(
		token,
		&models.CustomClaims{},
		func(token *jwt.Token) (any, error) {
			return as.EncryptionKey, nil
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

func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func isValidPassword(password string) bool {
	regexPattern := `^.{8,}$`
	match, _ := regexp.MatchString(regexPattern, password)
	return match
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

func (as *AuthService) generateAccessJWT(userID int64, userUUID string) (string, error) {
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

func (as *AuthService) generateEmailVerifyJWT(email string) (string, error) {
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
		err := httperrors.NewError(err, http.StatusInternalServerError)
		return "", err
	}

	return tokenString, nil
}
