package service

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/agusespa/a3n/internal/helpers"
	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/repository"
	logger "github.com/agusespa/flogg"
	"golang.org/x/exp/slices"
)

type RealmService interface {
	GetRealmById(id int64) (models.RealmEntity, error)
	PutRealm(req models.RealmRequest) error
}

type DefaultRealmService struct {
	AppRepo repository.AppRepository
	Config  ConfigService
	Logger  logger.Logger
}

func NewDefaultRealmService(appRepo *repository.MySqlRepository, config *DefaultConfigService, logger logger.Logger) *DefaultRealmService {
	return &DefaultRealmService{
		AppRepo: appRepo,
		Config:  config,
		Logger:  logger}
}

func (rs *DefaultRealmService) GetRealmById(realmID int64) (models.RealmEntity, error) {
	realm, err := rs.AppRepo.ReadRealmById(realmID)
	if err != nil {
		rs.Logger.LogError(err)
		return models.RealmEntity{}, err
	}

	if err := validateRealm(realm); err != nil {
		rs.Logger.LogError(err)
		return models.RealmEntity{}, err
	}

	if realm.EmailVerify && (realm.EmailProvider.String == "" || realm.EmailSender.String == "" || realm.EmailAddr.String == "") {
		err := errors.New("EmailProvider, EmailSender, and EmailAddr must be set when email verification is enabled")
		rs.Logger.LogError(err)
		realm.EmailVerify = false
	}

	return realm, nil
}

func (rs *DefaultRealmService) PutRealm(req models.RealmRequest) error {
	if req.EmailAddr != "" {
		if !helpers.IsValidEmail(req.EmailAddr) {
			err := errors.New("not a valid email address")
			err = httperrors.NewError(err, http.StatusBadRequest)
			rs.Logger.LogError(err)
			return err
		}
	}

	refreshExp, err := helpers.StringToInt64(req.RefreshExp)
	if err != nil {
		err := errors.New("not a valid refresh expiration value")
		err = httperrors.NewError(err, http.StatusBadRequest)
		rs.Logger.LogError(err)
		return err
	}

	accessExp, err := helpers.StringToInt64(req.AccessExp)
	if err != nil {
		err := errors.New("not a valid access expiration value")
		err = httperrors.NewError(err, http.StatusBadRequest)
		rs.Logger.LogError(err)
		return err
	}

	emailAddr := helpers.ParseNullString(req.EmailAddr)
	emailProvider := helpers.ParseNullString(req.EmailProvider)
	emailSender := helpers.ParseNullString(req.EmailSender)
	emailVerify := req.EmailVerify == "on"

	if emailVerify && (!emailProvider.Valid || !emailAddr.Valid || !emailSender.Valid) {
		err := errors.New("can't enable hard verify without complete email provider config")
		err = httperrors.NewError(err, http.StatusBadRequest)
		rs.Logger.LogError(err)
		return err
	}

	if emailProvider.Valid && !slices.Contains(rs.Config.GetSupportedEmailProviders(), emailProvider.String) {
		err := errors.New("email provider is not supported")
		err = httperrors.NewError(err, http.StatusBadRequest)
		rs.Logger.LogError(err)
		return err
	}

	apiKey := helpers.ParseNullString(req.ApiKey)

	realm := models.RealmEntity{
		RealmID:       1,
		RealmName:     req.RealmName,
		RealmDomain:   req.RealmDomain,
		RefreshExp:    refreshExp,
		AccessExp:     accessExp,
		EmailVerify:   emailVerify,
		EmailAddr:     emailAddr,
		EmailProvider: emailProvider,
		EmailSender:   emailSender,
		ApiKey:        apiKey,
	}

	err = rs.AppRepo.UpdateRealm(realm)
	if err != nil {
		rs.Logger.LogError(err)
		return err
	}

	rs.Config.SetRealmConfig(realm)

	return nil
}

func validateRealm(r models.RealmEntity) error {
	if r.RealmName == "" {
		return fmt.Errorf("RealmName cannot be empty")
	}
	if r.RealmDomain == "" {
		return fmt.Errorf("RealmDomain cannot be empty")
	}
	if r.RefreshExp <= 0 {
		return fmt.Errorf("RefreshExp must be greater than zero")
	}
	if r.AccessExp <= 0 {
		return fmt.Errorf("AccessExp must be greater than zero")
	}
	return nil
}
