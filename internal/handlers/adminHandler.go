package handlers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/agusespa/a3n/internal/helpers"
	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/logger"
	"github.com/agusespa/a3n/internal/payload"
	"github.com/agusespa/a3n/internal/service"
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
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	data, err := h.ApiService.GetUserData(userID)
	if err != nil {
		w.Header().Set("HX-Redirect", "/a3n/admin/login")
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	tmplPath := filepath.Join("internal", "templates", "admin_dash.html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		h.Logger.LogError(err)
		message := `<div class="error">Something went wrong</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		h.Logger.LogError(err)
		message := `<div class="error">Something went wrong</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}
}

func (h *DefaultAdminHandler) HandleAdminLogin(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	tmplPath := filepath.Join("internal", "templates", "admin_login.html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		h.Logger.LogError(err)
		message := `<div class="error">Something went wrong</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		h.Logger.LogError(err)
		message := `<div class="error">Something went wrong</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}
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
