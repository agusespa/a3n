package service

import "github.com/agusespa/a3n/internal/models"

type ConfigService interface {
	GetMailConfig() *models.Email
	GetTokenConfig() *models.Token
	GetDatabaseConfig() *models.Database
	GetDomain() string
	GetSupportedEmailProviders() []string
	SetRealmConfig(realm models.RealmEntity)
}

type DefaultConfigService struct {
	Domain                  string
	Database                models.Database
	Token                   models.Token
	Email                   models.Email
	SupportedEmailProviders []string
}

func NewDefaultConfigService(realm models.RealmEntity, database models.Database, emailApiKey string) *DefaultConfigService {
	emailSender := models.Sender{Name: realm.EmailSender.String, Address: realm.EmailAddr.String}
	emailConfig := models.Email{Provider: realm.EmailProvider.String, Sender: emailSender, HardVerify: realm.EmailVerify, ApiKey: emailApiKey}
	emailProviderList := []string{"sendgrid"}

	var refreshExp int64
	if realm.RefreshExp == 0 {
		refreshExp = 525600 // defaults to a year
	} else {
		refreshExp = realm.RefreshExp
	}
	var accessExp int64
	if realm.AccessExp == 0 {
		accessExp = 5 // default to 5 minutes
	} else {
		accessExp = realm.AccessExp
	}
	tokenConfig := models.Token{RefreshExp: refreshExp, AccessExp: accessExp}

	return &DefaultConfigService{
		Domain:                  realm.RealmDomain,
		Database:                database,
		Token:                   tokenConfig,
		Email:                   emailConfig,
		SupportedEmailProviders: emailProviderList,
	}
}

func (cs *DefaultConfigService) GetMailConfig() *models.Email {
	return &cs.Email
}

func (cs *DefaultConfigService) GetTokenConfig() *models.Token {
	return &cs.Token
}

func (cs *DefaultConfigService) GetDatabaseConfig() *models.Database {
	return &cs.Database
}

func (cs *DefaultConfigService) GetDomain() string {
	return cs.Domain
}

func (cs *DefaultConfigService) GetSupportedEmailProviders() []string {
	return cs.SupportedEmailProviders
}

func (cs *DefaultConfigService) SetRealmConfig(realm models.RealmEntity) {
	cs.Domain = realm.RealmDomain

	updatedEmailConfig := models.Email{}
	cs.Email = updatedEmailConfig

	updatedTokenConfig := models.Token{RefreshExp: realm.RefreshExp, AccessExp: realm.AccessExp}
	cs.Token = updatedTokenConfig
}
