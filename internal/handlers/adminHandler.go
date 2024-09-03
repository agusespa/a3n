package handlers

import (
	"net/http"

	"github.com/a-h/templ"
	"github.com/agusespa/a3n/internal/templates"
)

type AdminHandler interface {
	HandleAdminDashboard(w http.ResponseWriter, r *http.Request)
	HandleAdminLogin(w http.ResponseWriter, r *http.Request)
}

type DefaultAdminHandler struct {
}

func NewDefaultAdminHandler() *DefaultAdminHandler {
	return &DefaultAdminHandler{}
}

func (h *DefaultAdminHandler) HandleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated
	// If not, redirect to login page
	adminComponent := templates.Dashboard()
	templ.Handler(adminComponent).ServeHTTP(w, r)
}

func (h *DefaultAdminHandler) HandleAdminLogin(w http.ResponseWriter, r *http.Request) {
	loginComponent := templates.Login()
	templ.Handler(loginComponent).ServeHTTP(w, r)
}
