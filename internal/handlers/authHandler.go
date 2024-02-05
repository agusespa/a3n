package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/agusespa/ecom-be/auth/internal/errors"
	"github.com/agusespa/ecom-be/auth/internal/models"
	"github.com/agusespa/ecom-be/auth/internal/payload"
	"github.com/agusespa/ecom-be/auth/internal/service"
)

type AuthHandler struct {
	AuthService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{AuthService: authService}
}

func (h *AuthHandler) HandleUserRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		err := errors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	var authReq models.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
		http.Error(w, "Error parsing request body", http.StatusBadRequest)
		return
	}

	id, err := h.AuthService.RegisterNewUser(authReq)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.RegistrationResponse{
		UserID: id,
	}

	payload.Write(w, r, res)
}

func (h *AuthHandler) HandleUserLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		err := errors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.NewError(nil, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	username, password, err := extractBasicAuthCredentials(authHeader)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	authData, err := h.AuthService.LoginUser(username, password)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.UserAuthData{
		UserUUID:     authData.UserUUID,
		Email:        authData.Email,
		AccessToken:  authData.AccessToken,
		RefreshToken: authData.RefreshToken,
	}

	payload.Write(w, r, res)
}

func (h *AuthHandler) HandleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		err := errors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.NewError(nil, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	authParts := strings.Split(authHeader, " ")
	if len(authParts) != 2 || authParts[0] != "Bearer" {
		err := errors.NewError(nil, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	bearerToken := authParts[1]

	accessToken, err := h.AuthService.RefreshToken(bearerToken)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.RefreshRequestResponse{
		Token: accessToken,
	}

	payload.Write(w, r, res)
}

func (h *AuthHandler) HandleUserAuthentication(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		err := errors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.NewError(nil, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	authParts := strings.Split(authHeader, " ")
	if len(authParts) != 2 || authParts[0] != "Bearer" {
		err := errors.NewError(nil, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	bearerToken := authParts[1]

	claims, err := h.AuthService.ValidateToken(bearerToken)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.AuthenticationResponse{
		UserUUID: claims.UserUUID,
	}

	payload.Write(w, r, res)
}

func extractBasicAuthCredentials(authHeader string) (username, password string, err error) {
	if !strings.HasPrefix(authHeader, "Basic ") {
		err = errors.NewError(nil, http.StatusBadRequest)
		return
	}

	credsEncoded := strings.TrimPrefix(authHeader, "Basic ")
	credsDecoded, err := base64.StdEncoding.DecodeString(credsEncoded)
	if err != nil {
		err = errors.NewError(nil, http.StatusBadRequest)
		return
	}

	creds := strings.SplitN(string(credsDecoded), ":", 2)
	if len(creds) != 2 {
		err = errors.NewError(nil, http.StatusBadRequest)
		return
	}

	username = creds[0]
	password = creds[1]
	return
}
