package handlers

import (
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

	var authReq models.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&authReq); err != nil {
		http.Error(w, "Error parsing request body", http.StatusBadRequest)
		return
	}

	authData, err := h.AuthService.LoginUser(authReq)
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
