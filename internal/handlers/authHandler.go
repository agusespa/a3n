package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/agusespa/a3n/internal/helpers"
	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/payload"
	"github.com/agusespa/a3n/internal/service"
	logger "github.com/agusespa/flogg"
)

type AuthHandler interface {
	HandleUser(w http.ResponseWriter, r *http.Request)
	HandleUserLogin(w http.ResponseWriter, r *http.Request)
	HandleUserRefresh(w http.ResponseWriter, r *http.Request)
	HandleUserAuthentication(w http.ResponseWriter, r *http.Request)
	HandleTokenRevocation(w http.ResponseWriter, r *http.Request)
	HandleAllUserTokensRevocation(w http.ResponseWriter, r *http.Request)
}

type DefaultAuthHandler struct {
	AuthService service.AuthService
	Logger      logger.Logger
}

func NewDefaultAuthHandler(authService service.AuthService, logger logger.Logger) *DefaultAuthHandler {
	return &DefaultAuthHandler{AuthService: authService, Logger: logger}
}

func (h *DefaultAuthHandler) HandleUser(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	path := strings.TrimPrefix(r.URL.Path, "/auth/user/")
	parts := strings.Split(path, "/")
	userID, err := helpers.StringToInt64(parts[0])
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	switch {
	case len(parts) < 2:
		// user/{id}
		h.handleUserData(w, r, userID)
	case len(parts) == 2 && parts[1] == "verify":
		// user/{id}/verify
		h.handleUserEmailVerification(w, r, userID)
	case len(parts) == 2 && parts[1] == "email":
		// user/{id}/email
		h.handleUserEmailChange(w, r, userID)
	case len(parts) == 2 && parts[1] == "password":
		// user/{id}/password
		h.handleUserPasswordChange(w, r, userID)
	default:
		http.NotFound(w, r)
	}
}

func (h *DefaultAuthHandler) handleUserData(w http.ResponseWriter, r *http.Request, userID int64) {
	if r.Method == http.MethodPost {
		h.handlePostUserData(w, r)
		return
	} else {
		if userID == 0 {
			err := errors.New("User ID required")
			err = httperrors.NewError(err, http.StatusBadRequest)
			h.Logger.LogError(err)
			payload.WriteError(w, r, err)
			return
		}

		_, err := h.authenticateRequest(r, userID)
		if err != nil {
			err = httperrors.NewError(err, http.StatusUnauthorized)
			h.Logger.LogError(err)
			payload.WriteError(w, r, err)
			return
		}

		if r.Method == http.MethodGet {
			h.handleGetUserData(w, r, userID)
			return

		} else if r.Method == http.MethodDelete {
			h.handleDeleteUserData(w, r, userID)
			return
		}
	}

	h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
	err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
	payload.WriteError(w, r, err)
}

func (h *DefaultAuthHandler) HandleUserLogin(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodPost {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	var authReq models.AuthRequest
	err := r.ParseForm()
	if err != nil {
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}
	authReq.Email = r.Form.Get("username")
	authReq.Password = r.Form.Get("password")

	if authReq.Email == "" || authReq.Password == "" {
		err := errors.New("missing credentials")
		err = httperrors.NewError(err, http.StatusUnauthorized)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	authData, err := h.AuthService.GetUserLogin(authReq.Email, authReq.Password)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	acceptHeader := r.Header.Get("Accept")
	if strings.HasPrefix(acceptHeader, "application/json+cookie") {
		refresh_cookie := h.AuthService.BuildCookie("refresh_token", authData.RefreshToken, models.CookieOptions{Path: "/auth/refresh", Expiration: models.Refresh})
		access_cookie := h.AuthService.BuildCookie("access_token", authData.AccessToken, models.CookieOptions{Path: "/auth", Expiration: models.Access})
		cookies := []*http.Cookie{refresh_cookie, access_cookie}

		res := models.UserAuthData{
			UserID:   authData.UserID,
			UserUUID: authData.UserUUID,
		}
		payload.Write(w, r, res, cookies)
	} else {
		res := models.UserAuthData{
			UserID:       authData.UserID,
			UserUUID:     authData.UserUUID,
			AccessToken:  authData.AccessToken,
			RefreshToken: authData.RefreshToken,
		}
		payload.Write(w, r, res, nil)
	}
}

func (h *DefaultAuthHandler) handleUserEmailChange(w http.ResponseWriter, r *http.Request, userID int64) {
	if r.Method != http.MethodPut {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	_, err := h.authenticateRequest(r, userID)
	if err != nil {
		err = httperrors.NewError(err, http.StatusUnauthorized)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	var req models.CredentialsChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	if req.Email == "" || req.Password == "" {
		err := errors.New("missing credentials")
		err = httperrors.NewError(err, http.StatusUnauthorized)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	if req.NewEmail == "" {
		err := errors.New("missing new email address")
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	if !helpers.IsValidEmail(req.NewEmail) {
		err := errors.New("not a valid email address")
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	err = h.AuthService.PutUserEmail(req.Email, req.Password, req.NewEmail)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	payload.Write(w, r, nil, nil)
}

func (h *DefaultAuthHandler) handleUserPasswordChange(w http.ResponseWriter, r *http.Request, userID int64) {
	if r.Method != http.MethodPut {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	_, err := h.authenticateRequest(r, userID)
	if err != nil {
		err = httperrors.NewError(err, http.StatusUnauthorized)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	var req models.CredentialsChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	if req.Email == "" || req.Password == "" {
		err := errors.New("missing credentials")
		err = httperrors.NewError(err, http.StatusUnauthorized)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	if req.NewPassword == "" {
		err := errors.New("missing new password")
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	if !helpers.IsValidPassword(req.NewPassword) {
		err := errors.New("password doesn't meet minimum criteria")
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	err = h.AuthService.PutUserPassword(req.Email, req.Password, req.NewPassword)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	payload.Write(w, r, nil, nil)
}

func (h *DefaultAuthHandler) HandleUserRefresh(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodGet {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	bearerToken := ""
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		bearerToken = strings.Split(authHeader, " ")[1]
	} else {
		cookie, err := r.Cookie("refresh_token")
		if err == nil {
			bearerToken = cookie.Value
		}
	}

	if bearerToken == "" {
		err := errors.New("missing refresh token")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	accessToken, userID, err := h.AuthService.GetFreshAccessToken(bearerToken)
	if err != nil {
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	acceptHeader := r.Header.Get("Accept")
	if acceptHeader == "application/json+cookie" {
		res := models.RefreshRequestResponse{
			UserID: userID,
		}
		access_cookie := h.AuthService.BuildCookie("access_token", accessToken, models.CookieOptions{Path: "/auth", Expiration: models.Access})
		cookies := []*http.Cookie{access_cookie}
		payload.Write(w, r, res, cookies)
	} else {
		res := models.RefreshRequestResponse{
			UserID:      userID,
			AccessToken: accessToken,
		}
		payload.Write(w, r, res, nil)
	}
}

func (h *DefaultAuthHandler) authenticateRequest(r *http.Request, requestedUserID int64) (models.CustomClaims, error) {
	bearerToken := ""
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		bearerToken = strings.Split(authHeader, " ")[1]
	} else {
		cookie, err := r.Cookie("access_token")
		if err == nil {
			bearerToken = cookie.Value
		}
	}

	if bearerToken == "" {
		err := errors.New("missing access token")
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return models.CustomClaims{}, err
	}

	claims, err := h.AuthService.ValidateToken(bearerToken)
	if err != nil {
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return models.CustomClaims{}, err
	}

	if requestedUserID != 0 && claims.User.UserID != requestedUserID {
		err := errors.New("user doesn't have permissions to access this data")
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return models.CustomClaims{}, err
	}

	return claims, nil
}

func (h *DefaultAuthHandler) handleGetUserData(w http.ResponseWriter, r *http.Request, userID int64) {
	data, err := h.AuthService.GetUserData(userID)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	payload.Write(w, r, data, nil)
}

func (h *DefaultAuthHandler) handleDeleteUserData(w http.ResponseWriter, r *http.Request, userID int64) {
	err := h.AuthService.DeleteUserByID(userID)
	if err != nil {
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusInternalServerError)
		payload.WriteError(w, r, err)
		return
	}
}

func (h *DefaultAuthHandler) handlePostUserData(w http.ResponseWriter, r *http.Request) {
	var userReq models.UserRequest
	if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	if userReq.FirstName == "" || userReq.LastName == "" {
		err := errors.New("name not provided")
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	if userReq.Email == "" || userReq.Password == "" {
		err := errors.New("missing credentials")
		err = httperrors.NewError(err, http.StatusUnauthorized)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	if !helpers.IsValidEmail(userReq.Email) {
		err := errors.New("not a valid email address")
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}
	if !helpers.IsValidPassword(userReq.Password) {
		err := errors.New("password doesn't meet minimum criteria")
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

	payload.Write(w, r, res, nil)
}

func (h *DefaultAuthHandler) handleUserEmailVerification(w http.ResponseWriter, r *http.Request, userID int64) {
	if r.Method != http.MethodPut {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	claims, err := h.authenticateRequest(r, userID)
	if err != nil {
		err = httperrors.NewError(err, http.StatusUnauthorized)
		h.Logger.LogError(err)
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

	payload.Write(w, r, nil, nil)
}

func (h *DefaultAuthHandler) HandleUserAuthentication(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodGet {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	claims, err := h.authenticateRequest(r, 0)
	if err != nil {
		err = httperrors.NewError(err, http.StatusUnauthorized)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	if claims.Type != "access" {
		err := errors.New("invalid jwt claim")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
	}

	w.Header().Set("X-Auth-ID", fmt.Sprint(claims.User.UserID))
	w.Header().Set("X-Auth-UUID", claims.User.UserUUID)
	w.Header().Set("X-Auth-Roles", strings.Join(claims.Roles, ", "))

	payload.Write(w, r, nil, nil)
}

func (h *DefaultAuthHandler) HandleTokenRevocation(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodDelete {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.New("missing refresh token")
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

	payload.Write(w, r, "token successfully revoked", nil)
}

func (h *DefaultAuthHandler) HandleAllUserTokensRevocation(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodDelete {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.New("missing refresh token")
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

	payload.Write(w, r, "all user tokens successfully revoked", nil)
}
