package handlers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/a-h/templ"
	"github.com/agusespa/a3n/internal/helpers"
	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/logger"
	"github.com/agusespa/a3n/internal/payload"
	"github.com/agusespa/a3n/internal/service"
	"github.com/agusespa/a3n/internal/templates"
)

type AdminHandler interface {
	HandleAdminDashboard(w http.ResponseWriter, r *http.Request)
	HandleAdminLogin(w http.ResponseWriter, r *http.Request)
}

type DefaultAdminHandler struct {
	ApiService service.ApiService
	Logger     logger.Logger
}

func NewDefaultAdminHandler(authService service.ApiService, logger logger.Logger) *DefaultAdminHandler {
	return &DefaultAdminHandler{ApiService: authService, Logger: logger}
}

func (h *DefaultAdminHandler) HandleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	userID, err := h.authenticateAdminUser(r)
	if err != nil {
		w.Header().Set("HX-Redirect", "/a3n/admin/login")
		payload.WriteError(w, r, err)
		return
	}

	data, err := h.ApiService.GetUserData(userID)
	w.Header().Set("HX-Redirect", "/a3n/admin/login")
	if err != nil {
		payload.WriteError(w, r, err)
		return
	}

	adminComponent := templates.Dashboard(data)
	templ.Handler(adminComponent).ServeHTTP(w, r)
}

func (h *DefaultAdminHandler) HandleAdminLogin(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	loginComponent := templates.Login()
	templ.Handler(loginComponent).ServeHTTP(w, r)
}

func (h *DefaultAdminHandler) authenticateAdminUser(r *http.Request) (int64, error) {
	bearerToken := ""

	cookie, err := r.Cookie("access_token")
	if err == nil {
		decodedValue, err := base64.URLEncoding.DecodeString(cookie.Value)
		if err == nil {
			bearerToken = string(decodedValue)
		}
	}

	if bearerToken == "" {
		err := errors.New("missing access token")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return 0, err
	}

	claims, err := h.ApiService.ValidateToken(bearerToken)
	if err != nil {
		return 0, err
	}

	if claims.Type != "admin" {
		err := errors.New("invalid jwt claim")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return 0, err
	}

	if claims.IpAddr != helpers.GetIP(r) {
		err := errors.New("invalid ip address")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return 0, err
	}

	return claims.User.UserID, nil
}
