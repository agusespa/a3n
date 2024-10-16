package handlers

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"

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

//go:embed templates/*.html
var templatesFS embed.FS

func (h *DefaultAdminHandler) HandleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		err := errors.New("missing refresh token")
		err = httperrors.NewError(err, http.StatusUnauthorized)
		h.Logger.LogError(err)
		message := `<div class="error">Missing refresh token</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	claims, err := h.ApiService.AuthenticateAdminUser(cookie.Value, r)
	if err != nil {
		h.Logger.LogError(err)
		message := `<div class="error">Failed authentication</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	data, err := h.ApiService.GetUserData(claims.User.UserID)
	if err != nil {
		h.Logger.LogError(err)
		message := `<div class="error">Failed authentication</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	tmplPath := filepath.Join("templates", "admin_dash.html")
	tmpl, err := template.ParseFS(templatesFS, tmplPath)
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

	tmplPath := filepath.Join("templates", "admin_login.html")
	tmpl, err := template.ParseFS(templatesFS, tmplPath)
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
