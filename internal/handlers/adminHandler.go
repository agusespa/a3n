package handlers

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/payload"
	"github.com/agusespa/a3n/internal/service"
	logger "github.com/agusespa/flogg"
)

type AdminHandler interface {
	HandleAdminDashboard(w http.ResponseWriter, r *http.Request)
	HandleAdminActions(w http.ResponseWriter, r *http.Request)
	HandleAdminSettings(w http.ResponseWriter, r *http.Request)
	HandleAdminLogin(w http.ResponseWriter, r *http.Request)
}

type DefaultAdminHandler struct {
	ApiService   service.ApiService
	RealmService service.RealmService
	Config       service.ConfigService
	Logger       logger.Logger
}

func NewDefaultAdminHandler(authService service.ApiService, realmService service.RealmService, config service.ConfigService, logger logger.Logger) *DefaultAdminHandler {
	return &DefaultAdminHandler{ApiService: authService, RealmService: realmService, Config: config, Logger: logger}
}

//go:embed templates/*.html
var templatesFS embed.FS

func (h *DefaultAdminHandler) HandleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	claims, err := h.getAuthClaims(r)
	if err != nil {
		message := `<div class="error">Failed authentication</div>`
		w.Header().Set("HX-Redirect", "/admin/login")
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

	tmplPath := filepath.Join("templates", "admin_dash_layout.html")
	tmpl, err := template.ParseFS(templatesFS, tmplPath)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		h.Logger.LogError(err)
		message := `<div class="error">Something went wrong</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	err = payload.WriteTemplate(tmpl, data, w, r)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		h.Logger.LogError(err)
		message := `<div class="error">Something went wrong</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}
}

func (h *DefaultAdminHandler) getAuthClaims(r *http.Request) (models.CustomClaims, error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		err := errors.New("missing refresh token")
		err = httperrors.NewError(err, http.StatusUnauthorized)
		h.Logger.LogError(err)
		return models.CustomClaims{}, err
	}

	claims, err := h.ApiService.AuthenticateAdminUser(cookie.Value, r)
	if err != nil {
		err = httperrors.NewError(err, http.StatusUnauthorized)
		h.Logger.LogError(err)
		return models.CustomClaims{}, err
	}
	return claims, nil
}

func (h *DefaultAdminHandler) HandleAdminActions(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	_, err := h.getAuthClaims(r)
	if err != nil {
		message := `<div class="error">Failed authentication</div>`
		w.Header().Set("HX-Redirect", "/admin/login")
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	tmplPath := filepath.Join("templates", "admin_dash_actions.html")
	tmpl, err := template.ParseFS(templatesFS, tmplPath)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		h.Logger.LogError(err)
		message := `<div class="error">Something went wrong</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	err = payload.WriteTemplate(tmpl, nil, w, r)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		h.Logger.LogError(err)
		message := `<div class="error">Something went wrong</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}
}

func (h *DefaultAdminHandler) HandleAdminSettings(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	_, err := h.getAuthClaims(r)
	if err != nil {
		message := `<div class="error">Failed authentication</div>`
		w.Header().Set("HX-Redirect", "/admin/login")
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	realm, err := h.RealmService.GetRealmById(1)
	if err != nil {
		h.Logger.LogError(err)
		message := `<div class="error">Failed request</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	tmplPath := filepath.Join("templates", "admin_dash_settings.html")
	tmpl, err := template.ParseFS(templatesFS, tmplPath)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		h.Logger.LogError(err)
		message := `<div class="error">Something went wrong</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	type TemplateData struct {
		Realm     models.RealmEntity
		Providers []string
	}
	data := TemplateData{
		Realm:     realm,
		Providers: h.Config.GetSupportedEmailProviders(),
	}

	err = payload.WriteTemplate(tmpl, data, w, r)
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

	err = payload.WriteTemplate(tmpl, nil, w, r)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		h.Logger.LogError(err)
		message := `<div class="error">Something went wrong</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}
}
