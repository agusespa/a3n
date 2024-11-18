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

type ApiHandler interface {
	HandleUser(w http.ResponseWriter, r *http.Request)
}

type DefaultApiHandler struct {
	AuthService service.AuthService
	Config      service.ConfigService
	Logger      logger.Logger
}

func NewDefaultApiHandler(authService service.AuthService, config service.ConfigService, logger logger.Logger) *DefaultApiHandler {
	return &DefaultApiHandler{AuthService: authService, Config: config, Logger: logger}
}

func (h *DefaultApiHandler) HandleUser(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	path := strings.TrimPrefix(r.URL.Path, "/api/user")

	var userID int64 = 0
	var userUUID = ""

	if path != "" {
		if strings.HasPrefix(path, "/") {
			path = strings.TrimPrefix(path, "/")
			parts := strings.Split(path, "/")

			if len(parts) > 1 {
				http.NotFound(w, r)
				return
			}

			if parts[0] == "" {
				err := errors.New("User ID required")
				err = httperrors.NewError(err, http.StatusBadRequest)
				h.Logger.LogError(err)
				payload.WriteError(w, r, err)
				return
			}

			id, err := helpers.StringToInt64(parts[0])
			if err != nil {
				err = httperrors.NewError(err, http.StatusInternalServerError)
				h.Logger.LogError(err)
				payload.WriteError(w, r, err)
				return
			}
			userID = id

		} else if strings.HasPrefix(path, "?") {
			uuid, err := helpers.ReadQuery(r, "uuid")
			if err != nil {
				err = httperrors.NewError(err, http.StatusBadRequest)
				h.Logger.LogError(err)
				payload.WriteError(w, r, err)
				return
			}
			userUUID = uuid

		} else {
			http.NotFound(w, r)
			return
		}
	}

	h.handleUserData(w, r, userID, userUUID)
}

func (h *DefaultApiHandler) handleUserData(w http.ResponseWriter, r *http.Request, userID int64, userUUID string) {
	if r.Method == http.MethodPost {
		h.handlePostUserData(w, r)
		return

	} else {
		if userID == 0 || userUUID == "" {
			err := httperrors.NewError(errors.New("id not provided"), http.StatusBadRequest)
			h.Logger.LogError(err)
			payload.WriteError(w, r, err)
			return
		}

		err := h.authenticateRequest(r)
		if err != nil {
			err = httperrors.NewError(err, http.StatusUnauthorized)
			h.Logger.LogError(err)
			payload.WriteError(w, r, err)
			return
		}

		if r.Method == http.MethodGet {
			h.handleGetUserData(w, r, userID, userUUID)
			return
		} else if r.Method == http.MethodDelete {
			h.handleDeleteUserData(w, r, userID, userUUID)
			return
		}
	}

	h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
	err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
	payload.WriteError(w, r, err)
}

func (h *DefaultApiHandler) authenticateRequest(r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := errors.New("missing api key")
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return err
	}

	if authHeader == h.Config.GetApiKey() {
		err := errors.New("invalid api key")
		err = httperrors.NewError(err, http.StatusUnauthorized)
		return err
	}
	return nil
}

func (h *DefaultApiHandler) handleGetUserData(w http.ResponseWriter, r *http.Request, userID int64, userUUID string) {
	if userID != 0 {
		// TODO get by uuid
		return
	} else {
		// TODO get all
		return
	}
}

func (h *DefaultApiHandler) handleDeleteUserData(w http.ResponseWriter, r *http.Request, userID int64, userUUID string) {
	var err error
	if userID != 0 {
		err = h.AuthService.DeleteUserByID(userID)
	} else {
		err = h.AuthService.DeleteUserByUUID(userUUID)
	}

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
