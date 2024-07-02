package service

import (
	"os"
	"strings"
	"testing"

	"github.com/agusespa/a3n/mocks"
)

var es *AuthEmailService

func TestMain(m *testing.M) {
	es = &AuthEmailService{
		Provider:        "sendgrid",
		ClientDomain:    "https://example.com",
		SenderName:      "Test Sender",
		SenderAddr:      "sender@example.com",
		BackgroundColor: "#F0F0F0",
		FontColor:       "#333333",
		LinkColor:       "#0000FF",
		Logger:          mocks.NewMockLogger(false),
	}

	code := m.Run()

	os.Exit(code)
}

func TestBuildVerificationEmail(t *testing.T) {
	email := es.BuildVerificationEmail("John", "Doe", "john.doe@example.com", "test-token")

	if email.From.Name != "Test Sender" {
		t.Errorf("Expected From.Name to be 'Test Sender', got '%s'", email.From.Name)
	}
	if email.From.Address != "sender@example.com" {
		t.Errorf("Expected From.Address to be 'sender@example.com', got '%s'", email.From.Address)
	}
	if email.Personalizations[0].To[0].Name != "John Doe" {
		t.Errorf("Expected To[0].Name to be 'John Doe', got '%s'", email.Personalizations[0].To[0].Name)
	}
	if email.Personalizations[0].To[0].Address != "john.doe@example.com" {
		t.Errorf("Expected To[0].Address to be 'john.doe@example.com', got '%s'", email.Personalizations[0].To[0].Address)
	}
	if email.Subject != "Verify email address" {
		t.Errorf("Expected Subject to be 'Verify email address', got '%s'", email.Subject)
	}
	if !strings.Contains(email.Content[0].Value, "https://example.com/verify/test-token") {
		t.Errorf("Expected plain text content to contain verification link, but it didn't")
	}
	if !strings.Contains(email.Content[1].Value, "https://example.com/verify/test-token") {
		t.Errorf("Expected HTML content to contain verification link, but it didn't")
	}
}
