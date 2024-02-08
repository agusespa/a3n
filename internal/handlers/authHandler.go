package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/agusespa/autz/internal/httperrors"
	"github.com/agusespa/autz/internal/models"
	"github.com/agusespa/autz/internal/payload"
	"github.com/agusespa/autz/internal/service"
)

type AuthHandler struct {
	AuthService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{AuthService: authService}
}

func (h *AuthHandler) HandleUserRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	var authReq models.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
		err := httperrors.NewError(err, http.StatusBadRequest)
		payload.WriteError(w, r, err)
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
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := httperrors.NewError(nil, http.StatusUnauthorized)
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
		UserID:       authData.UserID,
		UserUUID:     authData.UserUUID,
		AccessToken:  authData.AccessToken,
		RefreshToken: authData.RefreshToken,
	}

	payload.Write(w, r, res)
}

func (h *AuthHandler) HandleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := httperrors.NewError(nil, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	bearerToken := strings.Split(authHeader, " ")[1]

	accessToken, err := h.AuthService.RefreshToken(bearerToken)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.RefreshRequestResponse{
		AccessToken: accessToken,
	}

	payload.Write(w, r, res)
}

func (h *AuthHandler) HandleUserAuthentication(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := httperrors.NewError(nil, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	bearerToken := strings.Split(authHeader, " ")[1]
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
		err = httperrors.NewError(nil, http.StatusBadRequest)
		return "", "", err
	}

	credentialsEncoded := strings.TrimPrefix(authHeader, "Basic ")
	credsentialsDecoded, err := base64.StdEncoding.DecodeString(credentialsEncoded)
	if err != nil {
		err = httperrors.NewError(nil, http.StatusBadRequest)
		return "", "", err
	}

	credentials := strings.SplitN(string(credsentialsDecoded), ":", 2)
	if len(credentials) != 2 {
		err = httperrors.NewError(nil, http.StatusBadRequest)
		return "", "", err
	}

	username = credentials[0]
	password = credentials[1]
	return
}

func (h *AuthHandler) HandleTokenRevocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := httperrors.NewError(nil, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	bearerToken := strings.Split(authHeader, " ")[1]

	accessToken, err := h.AuthService.RefreshToken(bearerToken)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.RefreshRequestResponse{
		AccessToken: accessToken,
	}

	payload.Write(w, r, res)
}
