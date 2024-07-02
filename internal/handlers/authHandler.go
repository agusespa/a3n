package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/logger"
	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/payload"
	"github.com/agusespa/a3n/internal/service"
)

type AuthHandler interface {
	HandleUserRegister(w http.ResponseWriter, r *http.Request)
	HandleUserEmailChange(w http.ResponseWriter, r *http.Request)
	HandleUserPasswordChange(w http.ResponseWriter, r *http.Request)
	HandleUserLogin(w http.ResponseWriter, r *http.Request)
	HandleTokenRefresh(w http.ResponseWriter, r *http.Request)
	HandleUserEmailVerification(w http.ResponseWriter, r *http.Request)
	HandleUserAuthentication(w http.ResponseWriter, r *http.Request)
	HandleTokenRevocation(w http.ResponseWriter, r *http.Request)
	HandleUserTokensRevocation(w http.ResponseWriter, r *http.Request)
}

type UserAuthHandler struct {
	AuthService service.AuthService
	Logger      logger.Logger
}

func NewAuthHandler(authService service.AuthService, logger logger.Logger) *UserAuthHandler {
	return &UserAuthHandler{AuthService: authService, Logger: logger}
}

func (h *UserAuthHandler) HandleUserRegister(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodPost {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	var userReq models.UserRequest
	if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	id, err := h.AuthService.PostUser(userReq)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.RegistrationResponse{
		UserID: id,
	}

	payload.Write(w, r, res)
}

func (h *UserAuthHandler) HandleUserEmailChange(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodPut {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.New("no bearer token")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	username, password, err := h.extractBasicAuthCredentials(authHeader)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	var authReq models.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusBadRequest)
		payload.WriteError(w, r, err)
		return
	}

	id, err := h.AuthService.PutUserEmail(username, password, authReq.Email)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.RegistrationResponse{
		UserID: id,
	}

	payload.Write(w, r, res)
}

func (h *UserAuthHandler) HandleUserPasswordChange(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodPut {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.New("missing authorization header")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	username, password, err := h.extractBasicAuthCredentials(authHeader)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	var authReq models.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusBadRequest)
		payload.WriteError(w, r, err)
		return
	}

	id, err := h.AuthService.PutUserPassword(username, password, authReq.Password)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.RegistrationResponse{
		UserID: id,
	}

	payload.Write(w, r, res)
}

func (h *UserAuthHandler) HandleUserLogin(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodGet {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.New("missing authorization header")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	username, password, err := h.extractBasicAuthCredentials(authHeader)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	authData, err := h.AuthService.GetUserLogin(username, password)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.UserAuthData{
		UserID:       authData.UserID,
		UserUUID:     authData.UserUUID,
		AccessToken:  authData.AccessToken,
		RefreshToken: authData.RefreshToken,
	}

	payload.Write(w, r, res)
}

func (h *UserAuthHandler) HandleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodGet {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.New("missing authorization header")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	bearerToken := strings.Split(authHeader, " ")[1]

	accessToken, err := h.AuthService.GetRefreshToken(bearerToken)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.RefreshRequestResponse{
		AccessToken: accessToken,
	}

	payload.Write(w, r, res)
}

func (h *UserAuthHandler) HandleUserEmailVerification(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodPut {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.New("missing authorization header")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	bearerToken := strings.Split(authHeader, " ")[1]
	claims, err := h.AuthService.ValidateToken(bearerToken)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	if claims.Type != "email_verify" {
		err := errors.New("invalid jwt claim")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
	}

	err = h.AuthService.PutUserEmailVerification(claims.Email)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	payload.Write(w, r, nil)
}

func (h *UserAuthHandler) HandleUserAuthentication(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodGet {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.New("missing authorization header")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	bearerToken := strings.Split(authHeader, " ")[1]
	claims, err := h.AuthService.ValidateToken(bearerToken)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	if claims.Type != "access" {
		err := errors.New("invalid jwt claim")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
	}

	res := models.AuthenticationResponse{
		UserUUID: claims.User.UserUUID,
	}

	payload.Write(w, r, res)
}

func (h *UserAuthHandler) extractBasicAuthCredentials(authHeader string) (username, password string, err error) {
	if !strings.HasPrefix(authHeader, "Basic ") {
		err := errors.New("missing credentials")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusBadRequest)
		return "", "", err
	}

	credentialsEncoded := strings.TrimPrefix(authHeader, "Basic ")
	credsentialsDecoded, err := base64.StdEncoding.DecodeString(credentialsEncoded)
	if err != nil {
		h.Logger.LogError(err)
		err = httperrors.NewError(nil, http.StatusBadRequest)
		return "", "", err
	}

	credentials := strings.SplitN(string(credsentialsDecoded), ":", 2)
	if len(credentials) != 2 {
		h.Logger.LogError(errors.New("malformed credentials"))
		err = httperrors.NewError(nil, http.StatusBadRequest)
		return "", "", err
	}

	username = credentials[0]
	password = credentials[1]
	return
}

func (h *UserAuthHandler) HandleTokenRevocation(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodDelete {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.New("missing authorization header")
		h.Logger.LogError(err)
		err = httperrors.NewError(nil, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	bearerToken := strings.Split(authHeader, " ")[1]

	err := h.AuthService.DeleteToken(bearerToken)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	payload.Write(w, r, "token successfully revoked")
}

func (h *UserAuthHandler) HandleUserTokensRevocation(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodDelete {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.New("missing authorization header")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	bearerToken := strings.Split(authHeader, " ")[1]

	err := h.AuthService.DeleteAllTokens(bearerToken)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	payload.Write(w, r, "all user tokens successfully revoked")
}
