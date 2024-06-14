package mocks

import (
	"errors"
	"testing"

	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/service"
	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type MockSendGridClient struct {
	SendFunc func(email *mail.SGMailV3) (*rest.Response, error)
}

func (m *MockSendGridClient) Send(email *mail.SGMailV3) (*rest.Response, error) {
	return m.SendFunc(email)
}

func TestSendEmail(t *testing.T) {
	mockLogger := &MockLogger{}

	mockSendGridClient := &MockSendGridClient{
		SendFunc: func(email *mail.SGMailV3) (*sendgrid.Response, error) {
			// Simulate a successful send
			return &sendgrid.Response{StatusCode: 202, Body: "Accepted", Headers: nil}, nil
		},
	}

	config := models.Config{
		// Populate with necessary config data
	}
	emailService := service.NewEmailService(config, "dummy-api-key", mockLogger, mockSendGridClient)

	email := mail.NewV3Mail()
	// Populate email fields

	emailService.SendEmail(email)

	if len(mockLogger.LogInfoCalls) != 1 || mockLogger.LogInfoCalls[0] != "email sent" {
		t.Errorf("expected LogInfo to be called with 'email sent', but got %v", mockLogger.LogInfoCalls)
	}

	if len(mockLogger.LogDebugCalls) != 1 {
		t.Errorf("expected LogDebug to be called once, but got %d calls", len(mockLogger.LogDebugCalls))
	}

	if len(mockLogger.LogErrorCalls) != 0 {
		t.Errorf("expected LogError not to be called, but got %d calls", len(mockLogger.LogErrorCalls))
	}
}

func TestSendEmailFailure(t *testing.T) {
	mockLogger := &MockLogger{}

	mockSendGridClient := &MockSendGridClient{
		SendFunc: func(email *mail.SGMailV3) (*sendgrid.Response, error) {
			// Simulate a failure
			return nil, errors.New("failed to send email")
		},
	}

	config := models.Config{
		// Populate with necessary config data
	}
	emailService := service.NewEmailService(config, "dummy-api-key", mockLogger, mockSendGridClient)

	email := mail.NewV3Mail()
	// Populate email fields

	emailService.SendEmail(email)

	if len(mockLogger.LogInfoCalls) != 0 {
		t.Errorf("expected LogInfo not to be called, but got %d calls", len(mockLogger.LogInfoCalls))
	}

	if len(mockLogger.LogDebugCalls) != 0 {
		t.Errorf("expected LogDebug not to be called, but got %d calls", len(mockLogger.LogDebugCalls))
	}

	if len(mockLogger.LogErrorCalls) != 1 || mockLogger.LogErrorCalls[0].Error() != "failed to send email: failed to send email" {
		t.Errorf("expected LogError to be called with 'failed to send email: failed to send email', but got %v", mockLogger.LogErrorCalls)
	}
}
