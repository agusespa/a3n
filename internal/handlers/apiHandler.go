package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/payload"
	"github.com/agusespa/a3n/internal/service"
	logger "github.com/agusespa/flogg"
)

type ApiHandler interface {
	HandleUserData(w http.ResponseWriter, r *http.Request)
}

type DefaultApiHandler struct {
	AuthService service.AuthService
	Logger      logger.Logger
}

func NewDefaultApiHandler(apiService service.AuthService, logger logger.Logger) *DefaultAuthHandler {
	return &DefaultAuthHandler{AuthService: apiService, Logger: logger}
}

func (h *DefaultApiHandler) HandleUserData(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	bearerToken := ""
	authHeader := r.Header.Get("Authorization")
	bearerToken = strings.Split(authHeader, " ")[1]

	if bearerToken == "" {
		err := errors.New("missing api key")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusUnauthorized)
		payload.WriteError(w, r, err)
		return
	}

	if r.Method == http.MethodGet {
		h.handleGetUserData(w, r)
	} else if r.Method == http.MethodPost {
		h.handlePostUserData(w, r)
	} else if r.Method == http.MethodDelete {
		h.handleDeleteUserData(w, r)
	} else {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}
}

func (h *DefaultApiHandler) handleGetUserData(w http.ResponseWriter, r *http.Request) {
	uuidStr := r.URL.Query().Get("uuid")
	if uuidStr != "" {
		// TODO get by uuid
		return
	} else {
		// TODO get all
		return
	}
}

func (h *DefaultApiHandler) handleDeleteUserData(w http.ResponseWriter, r *http.Request) {
	uuidStr := r.URL.Query().Get("uuid")
	if uuidStr == "" {
		err := errors.New("missing uuid parameter")
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusBadRequest)
		payload.WriteError(w, r, err)
		return
	}

	err := h.AuthService.DeleteUser(uuidStr)
	if err != nil {
		h.Logger.LogError(err)
		err = httperrors.NewError(err, http.StatusInternalServerError)
		payload.WriteError(w, r, err)
		return
	}

	payload.Write(w, r, nil, nil)
}

func (h *DefaultApiHandler) handlePostUserData(w http.ResponseWriter, r *http.Request) {
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
