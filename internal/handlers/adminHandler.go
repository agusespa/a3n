package handlers

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"

	"github.com/agusespa/a3n/internal/helpers"
	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/payload"
	"github.com/agusespa/a3n/internal/service"
	logger "github.com/agusespa/flogg"
)

type AdminHandler interface {
	HandleAdminDashboardPage(w http.ResponseWriter, r *http.Request)
	HandleAdminActionsPage(w http.ResponseWriter, r *http.Request)
	HandleAdminSettingsPage(w http.ResponseWriter, r *http.Request)
	HandleAdminLoginPage(w http.ResponseWriter, r *http.Request)
	HandleAdminAuth(w http.ResponseWriter, r *http.Request)
	HandleAdminRefresh(w http.ResponseWriter, r *http.Request)
}

type DefaultAdminHandler struct {
	AuthService  service.AuthService
	RealmService service.RealmService
	Config       service.ConfigService
	Logger       logger.Logger
}

func NewDefaultAdminHandler(authService service.AuthService, realmService service.RealmService, config service.ConfigService, logger logger.Logger) *DefaultAdminHandler {
	return &DefaultAdminHandler{AuthService: authService, RealmService: realmService, Config: config, Logger: logger}
}

//go:embed templates/*.html
var templatesFS embed.FS

func (h *DefaultAdminHandler) HandleAdminDashboardPage(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	claims, err := h.getAuthClaims(r)
	if err != nil {
		message := `<div class="error">Failed authentication</div>`
		w.Header().Set("HX-Redirect", "/admin/login")
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	data, err := h.AuthService.GetUserData(claims.User.UserID)
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

	claims, err := h.AuthService.AuthenticateAdminUser(cookie.Value, r)
	if err != nil {
		err = httperrors.NewError(err, http.StatusUnauthorized)
		h.Logger.LogError(err)
		return models.CustomClaims{}, err
	}
	return claims, nil
}

func (h *DefaultAdminHandler) HandleAdminActionsPage(w http.ResponseWriter, r *http.Request) {
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

func (h *DefaultAdminHandler) HandleAdminSettingsPage(w http.ResponseWriter, r *http.Request) {
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

func (h *DefaultAdminHandler) HandleAdminLoginPage(w http.ResponseWriter, r *http.Request) {
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

func (h *DefaultAdminHandler) HandleAdminAuth(w http.ResponseWriter, r *http.Request) {
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
		message := `<div class="error">Missing credentials</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	adminAuthData, err := h.AuthService.GetAdminUserLogin(authReq.Email, authReq.Password, helpers.GetIP(r))
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
	access_cookie := h.AuthService.BuildCookie("refresh_token", adminAuthData.AccessToken, models.CookieOptions{Path: "/"})
	cookies := []*http.Cookie{access_cookie}
	payload.Write(w, r, res, cookies)
}

func (h *DefaultAdminHandler) HandleAdminRefresh(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodGet {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	bearerToken, err := r.Cookie("refresh_token")
	if err != nil {
		err := errors.New("missing refresh token")
		err = httperrors.NewError(err, http.StatusUnauthorized)
		h.Logger.LogError(err)
		message := `<div class="error">Missing refresh token</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	claims, err := h.AuthService.AuthenticateAdminUser(bearerToken.Value, r)
	if err != nil {
		message := `<div class="error">Failed authentication</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	token, err := h.AuthService.GenerateAdminSessionJWT(claims.User.UserID, claims.User.UserUUID, claims.Roles, helpers.GetIP(r))
	if err != nil {
		err := errors.New("failed generating jwt token")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusInternalServerError)
		message := `<div class="error">Internal server error</div>`
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	res := models.RefreshRequestResponse{
		UserID: claims.User.UserID,
	}
	access_cookie := h.AuthService.BuildCookie("refresh_token", token, models.CookieOptions{Path: "/", Expiration: models.Access})
	cookies := []*http.Cookie{access_cookie}
	payload.Write(w, r, res, cookies)
}
