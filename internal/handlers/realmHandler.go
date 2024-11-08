package handlers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/payload"
	"github.com/agusespa/a3n/internal/service"
	logger "github.com/agusespa/flogg"
)

type RealmHandler interface {
	HandleRealm(w http.ResponseWriter, r *http.Request)
}

type DefaultRealmHandler struct {
	RealmService service.RealmService
	Logger       logger.Logger
}

func NewDefaultRealmHandler(realmService service.RealmService, logger logger.Logger) *DefaultRealmHandler {
	return &DefaultRealmHandler{RealmService: realmService, Logger: logger}
}

func (h *DefaultRealmHandler) HandleRealm(w http.ResponseWriter, r *http.Request) {
	h.Logger.LogInfo(fmt.Sprintf("%s %v", r.Method, r.URL))

	if r.Method != http.MethodPut {
		h.Logger.LogError(fmt.Errorf("%s method not allowed for %v", r.Method, r.URL))
		err := httperrors.NewError(nil, http.StatusMethodNotAllowed)
		payload.WriteError(w, r, err)
		return
	}

	err := r.ParseForm()
	if err != nil {
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	realmReq := models.RealmRequest{}

	realmReq.RealmName = r.Form.Get("realm_name")
	if realmReq.RealmName == "" {
		err := errors.New("realm name not provided")
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	realmReq.RealmDomain = r.Form.Get("realm_domain")
	if realmReq.RealmDomain == "" {
		err := errors.New("realm domain not provided")
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	realmReq.RefreshExp = r.Form.Get("refresh_exp")
	if realmReq.RefreshExp == "" {
		err := errors.New("refresh token expiration not provided")
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	realmReq.AccessExp = r.Form.Get("access_exp")
	if realmReq.AccessExp == "" {
		err := errors.New("access token expiration not provided")
		err = httperrors.NewError(err, http.StatusBadRequest)
		h.Logger.LogError(err)
		payload.WriteError(w, r, err)
		return
	}

	realmReq.EmailVerify = r.Form.Get("email_verify")
	realmReq.EmailSender = r.Form.Get("email_sender")
	realmReq.EmailProvider = r.Form.Get("email_provider")
	realmReq.EmailAddr = r.Form.Get("email_addr")

	realmReq.ApiKey = r.Form.Get("api_key")

	err = h.RealmService.PutRealm(realmReq)
	if err != nil {
		message := fmt.Sprintf(`<div class="error">There was an error updating the realm: %v</div>`, err.Error())
		payload.WriteHTMLError(w, r, err, message)
		return
	}

	message := `<div class="success">Update successful</div>`
	payload.Write(w, r, message, nil)
}
