package mocks

import (
	"github.com/agusespa/a3n/internal/logger"
	"github.com/agusespa/a3n/internal/models"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type MockEmailService struct {
	SendEmailCalled                 bool
	SendEmailEmail                  mail.SGMailV3
	BuildVerificationEmailCalled    bool
	BuildVerificationEmailFirstName string
	BuildVerificationEmailLastName  string
	BuildVerificationEmailToAddr    string
	BuildVerificationEmailToken     string
	BuildVerificationEmailResult    mail.SGMailV3
}

func NewMockEmailService(config models.ApiConfig, key string, logger logger.FileLogger) *MockEmailService {
	return &MockEmailService{}
}

func (m *MockEmailService) SendEmail(email mail.SGMailV3) {
	m.SendEmailCalled = true
	m.SendEmailEmail = email
}

func (m *MockEmailService) BuildVerificationEmail(firstName, lastName, toAddr, token string) mail.SGMailV3 {
	m.BuildVerificationEmailCalled = true
	m.BuildVerificationEmailFirstName = firstName
	m.BuildVerificationEmailLastName = lastName
	m.BuildVerificationEmailToAddr = toAddr
	m.BuildVerificationEmailToken = token
	return m.BuildVerificationEmailResult
}
