package mocks

import "github.com/agusespa/a3n/internal/models"

type MockConfigService struct {
	Domain string
	Token  models.Token
	Email  models.Email
}

func NewMockConfigService() *MockConfigService {
	provider := "sendgrid"
	senderName := "Test Sender"
	senderAddr := "sender@example.com"
	emailSender := models.Sender{Name: senderName, Address: senderAddr}
	emailConfig := models.Email{Provider: provider, Sender: emailSender, HardVerify: true, ApiKey: "secret"}

	clientDomain := "https://example.com"
	var refreshExp int64 = 1440
	var accessExp int64 = 5
	tokenConfig := models.Token{RefreshExp: refreshExp, AccessExp: accessExp}

	return &MockConfigService{
		Domain: clientDomain,
		Token:  tokenConfig,
		Email:  emailConfig,
	}
}

func (cs *MockConfigService) GetMailConfig() *models.Email {
	return &cs.Email
}

func (cs *MockConfigService) GetTokenConfig() *models.Token {
	return &cs.Token
}

func (cs *MockConfigService) GetDatabaseConfig() *models.Database {
	return nil
}

func (cs *MockConfigService) GetDomain() string {
	return cs.Domain
}

func (cs *MockConfigService) GetSupportedEmailProviders() []string {
	return []string{"test"}
}

func (cs *MockConfigService) SetRealmConfig(realm models.RealmEntity) {
}
