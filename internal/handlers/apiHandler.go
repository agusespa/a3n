package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/agusespa/a3n/internal/helpers"
	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/logger"
	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/payload"
	"github.com/agusespa/a3n/internal/service"
)

type ApiHandler interface {
	HandleUserRegister(w http.ResponseWriter, r *http.Request)
	HandleUserEmailChange(w http.ResponseWriter, r *http.Request)
	HandleUserPasswordChange(w http.ResponseWriter, r *http.Request)
	HandleLogin(w http.ResponseWriter, r *http.Request)
	HandleUserLogin(w http.ResponseWriter, r *http.Request)
	HandleAdminLogin(w http.ResponseWriter, r *http.Request)
	HandleTokenRefresh(w http.ResponseWriter, r *http.Request)
	HandleUserEmailVerification(w http.ResponseWriter, r *http.Request)
	HandleUserAuthentication(w http.ResponseWriter, r *http.Request)
	HandleTokenRevocation(w http.ResponseWriter, r *http.Request)
	HandleAllUserTokensRevocation(w http.ResponseWriter, r *http.Request)
}

type DefaultApiHandler struct {
	ApiService service.ApiService
	Logger     logger.Logger
}

func NewDefaultApiHandler(authService service.ApiService, logger logger.Logger) *DefaultApiHandler {
	return &DefaultApiHandler{ApiService: authService, Logger: logger}
}

func (h *DefaultApiHandler) HandleUserRegister(w http.ResponseWriter, r *http.Request) {
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

	id, err := h.ApiService.PostUser(userReq)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.RegistrationResponse{
		UserID: id,
	}

	payload.Write(w, r, res, nil)
}

func (h *DefaultApiHandler) HandleUserEmailChange(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodPut {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
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

	id, err := h.ApiService.PutUserEmail(req.Email, req.Password, req.NewEmail)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.RegistrationResponse{
		UserID: id,
	}

	payload.Write(w, r, res, nil)
}

func (h *DefaultApiHandler) HandleUserPasswordChange(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodPut {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
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

	id, err := h.ApiService.PutUserPassword(req.Email, req.Password, req.NewPassword)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	res := models.RegistrationResponse{
		UserID: id,
	}

	payload.Write(w, r, res, nil)
}

func (h *DefaultApiHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodPost {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	isAdminClient := r.Header.Get("X-Admin-Request") == "true"

	if isAdminClient {
		h.HandleAdminLogin(w, r)
	} else {
		h.HandleUserLogin(w, r)
	}
}

func (h *DefaultApiHandler) HandleAdminLogin(w http.ResponseWriter, r *http.Request) {
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
		message := `<div class="error">Missing credentials</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	adminAuthData, err := h.ApiService.GetUserAdminLogin(authReq.Email, authReq.Password, helpers.GetIP(r))
	if err != nil {
		var statusCode int
		var message string
		if customErr, ok := err.(*httperrors.Error); ok {
			statusCode = customErr.Status()
		} else {
			statusCode = http.StatusInternalServerError
		}
		if statusCode == http.StatusForbidden {
			message = `<div class="error">Username not registered</div>`
		} else if statusCode == http.StatusNotFound {
			message = `<div class="error">Username not registered</div>`
		} else if statusCode == http.StatusUnauthorized {
			message = `<div class="error">Incorrect password</div>`
		} else {
			message = `<div class="error">Unknown error</div>`
		}
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	w.Header().Set("HX-Redirect", "/admin/dashboard")
	res := `<div class="success">Login successful. Redirecting...</div>`
	access_cookie := h.ApiService.BuildCookie("access_token", adminAuthData.AccessToken, models.CookieOptions{Path: "/admin"})
	cookies := []*http.Cookie{access_cookie}
	payload.Write(w, r, res, cookies)
}

func (h *DefaultApiHandler) HandleUserLogin(w http.ResponseWriter, r *http.Request) {
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

	authData, err := h.ApiService.GetUserLogin(authReq.Email, authReq.Password)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	acceptHeader := r.Header.Get("Accept")
	if strings.HasPrefix(acceptHeader, "application/json+cookie") {
		refresh_cookie := h.ApiService.BuildCookie("refresh_token", authData.RefreshToken, models.CookieOptions{Path: "/api/refresh", Expiration: models.Refresh})
		access_cookie := h.ApiService.BuildCookie("access_token", authData.AccessToken, models.CookieOptions{Path: "/api", Expiration: models.Access})
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

func (h *DefaultApiHandler) HandleTokenRefresh(w http.ResponseWriter, r *http.Request) {
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
	}

	if bearerToken == "" {
		cookie, err := r.Cookie("refresh_token")
		if err == nil {
			decodedValue, err := base64.URLEncoding.DecodeString(cookie.Value)
			if err == nil {
				bearerToken = string(decodedValue)
			}
		}
	}

	if bearerToken == "" {
		err := errors.New("missing refresh token")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	accessToken, userID, err := h.ApiService.GetFreshAccessToken(bearerToken)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	acceptHeader := r.Header.Get("Accept")
	if acceptHeader == "application/json+cookie" {
		res := models.RefreshRequestResponse{
			UserID: userID,
		}
		access_cookie := h.ApiService.BuildCookie("access_token", accessToken, models.CookieOptions{Path: "/authapi", Expiration: models.Access})
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

func (h *DefaultApiHandler) HandleUserData(w http.ResponseWriter, r *http.Request) {
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
	}

	if bearerToken == "" {
		cookie, err := r.Cookie("access_token")
		if err == nil {
			decodedValue, err := base64.URLEncoding.DecodeString(cookie.Value)
			if err == nil {
				bearerToken = string(decodedValue)
			}
		}
	}

	if bearerToken == "" {
		err := errors.New("missing access token")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	claims, err := h.ApiService.ValidateToken(bearerToken)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	userIDquery := r.URL.Query().Get("id")
	if userIDquery == "" {
		err := errors.New("missing id parameter")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusBadRequest)
		payload.WriteError(w, r, err)
		return
	}
	userID, err := strconv.ParseInt(userIDquery, 10, 64)
	if err != nil {
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusInternalServerError)
		payload.WriteError(w, r, err)
		return
	}

	if claims.User.UserID != userID {
		err := errors.New("user id missmatch")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	// TODO handle case of admin in claims

	data, err := h.ApiService.GetUserData(userID)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	payload.Write(w, r, data, nil)
}

func (h *DefaultApiHandler) HandleUserEmailVerification(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodPut {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	bearerToken := ""

	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		bearerToken = strings.Split(authHeader, " ")[1]
	}

	if bearerToken == "" {
		cookie, err := r.Cookie("access_token")
		if err == nil {
			decodedValue, err := base64.URLEncoding.DecodeString(cookie.Value)
			if err == nil {
				bearerToken = string(decodedValue)
			}
		}
	}

	if bearerToken == "" {
		err := errors.New("missing access token")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	claims, err := h.ApiService.ValidateToken(bearerToken)
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

	err = h.ApiService.PutUserEmailVerification(claims.Email)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	payload.Write(w, r, nil, nil)
}

func (h *DefaultApiHandler) HandleUserAuthentication(w http.ResponseWriter, r *http.Request) {
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
	}

	if bearerToken == "" {
		cookie, err := r.Cookie("access_token")
		if err == nil {
			decodedValue, err := base64.URLEncoding.DecodeString(cookie.Value)
			if err == nil {
				bearerToken = string(decodedValue)
			}
		}
	}

	if bearerToken == "" {
		err := errors.New("missing access token")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	claims, err := h.ApiService.ValidateToken(bearerToken)
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

	payload.Write(w, r, res, nil)
}

func (h *DefaultApiHandler) HandleTokenRevocation(w http.ResponseWriter, r *http.Request) {
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

	err := h.ApiService.DeleteToken(bearerToken)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	payload.Write(w, r, "token successfully revoked", nil)
}

func (h *DefaultApiHandler) HandleAllUserTokensRevocation(w http.ResponseWriter, r *http.Request) {
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

	err := h.ApiService.DeleteAllTokens(bearerToken)
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	payload.Write(w, r, "all user tokens successfully revoked", nil)
}
