package service

import (
	"database/sql"
	"testing"

	"github.com/agusespa/a3n/internal/models"
)

func TestGetMailConfig(t *testing.T) {
	configService := setupConfigService()
	emailConfig := configService.GetMailConfig()

	if emailConfig == nil {
		t.Fatal("expected emailConfig to be not nil")
	}
	if emailConfig.Provider != "sendgrid" {
		t.Errorf("expected Provider to be 'sendgrid', got %s", emailConfig.Provider)
	}
	if emailConfig.Sender.Address != "noreply@example.com" {
		t.Errorf("expected Sender.Address to be 'noreply@example.com', got %s", emailConfig.Sender.Address)
	}
	if emailConfig.HardVerify != true {
		t.Errorf("expected HardVerify to be true, got %v", emailConfig.HardVerify)
	}
}

func TestGetTokenConfig(t *testing.T) {
	configService := setupConfigService()
	tokenConfig := configService.GetTokenConfig()

	if tokenConfig == nil {
		t.Fatal("expected tokenConfig to be not nil")
	}
	if tokenConfig.RefreshExp != int64(1440) {
		t.Errorf("expected RefreshExp to be 1440, got %d", tokenConfig.RefreshExp)
	}
	if tokenConfig.AccessExp != int64(5) {
		t.Errorf("expected AccessExp to be 5, got %d", tokenConfig.AccessExp)
	}
}

func TestGetDatabaseConfig(t *testing.T) {
	configService := setupConfigService()
	databaseConfig := configService.GetDatabaseConfig()

	if databaseConfig == nil {
		t.Fatal("expected databaseConfig to be not nil")
	}
	if databaseConfig.User != "user" {
		t.Errorf("expected User to be 'user', got %s", databaseConfig.User)
	}
	if databaseConfig.Password != "password" {
		t.Errorf("expected Password to be 'password', got %s", databaseConfig.Password)
	}
	if databaseConfig.Address != "address" {
		t.Errorf("expected Address to be 'address', got %s", databaseConfig.Address)
	}
}

func TestGetDomain(t *testing.T) {
	configService := setupConfigService()
	domain := configService.GetDomain()

	if domain != "example.com" {
		t.Errorf("expected domain to be 'example.com', got %s", domain)
	}
}

func TestGetSupportedEmailProviders(t *testing.T) {
	configService := setupConfigService()
	providers := configService.GetSupportedEmailProviders()

	expectedProviders := []string{"sendgrid"}
	for i, provider := range providers {
		if provider != expectedProviders[i] {
			t.Errorf("expected provider %s, got %s", expectedProviders[i], provider)
		}
	}
}

func TestSetRealmConfig(t *testing.T) {
	configService := setupConfigService()

	updatedRealm := models.RealmEntity{
		RealmDomain:   "updated.com",
		RefreshExp:    2000,
		AccessExp:     15,
		EmailVerify:   false,
		EmailProvider: sql.NullString{String: "updated-provider", Valid: true},
		EmailSender:   sql.NullString{String: "updated@example.com", Valid: true},
		EmailAddr:     sql.NullString{String: "updated-noreply@example.com", Valid: true},
	}

	configService.SetRealmConfig(updatedRealm)

	if configService.GetDomain() != "updated.com" {
		t.Errorf("expected domain to be 'updated.com', got %s", configService.GetDomain())
	}
	tokenConfig := configService.GetTokenConfig()
	if tokenConfig.RefreshExp != 2000 || tokenConfig.AccessExp != 15 {
		t.Errorf("expected token config to be {RefreshExp: 2000, AccessExp: 15}, got {RefreshExp: %d, AccessExp: %d}", tokenConfig.RefreshExp, tokenConfig.AccessExp)
	}
	expectedMailConfig := "updated-provider"
	mailConfig := configService.GetMailConfig()
	if mailConfig.Provider != expectedMailConfig {
		t.Errorf("expected mail provider to be %v, got %v", expectedMailConfig, mailConfig.Provider)
	}
}

func setupConfigService() *DefaultConfigService {
	realm := models.RealmEntity{
		RealmDomain:   "example.com",
		RefreshExp:    1440,
		AccessExp:     5,
		EmailVerify:   true,
		EmailProvider: sql.NullString{String: "sendgrid", Valid: true},
		EmailSender:   sql.NullString{String: "support@example.com", Valid: true},
		EmailAddr:     sql.NullString{String: "noreply@example.com", Valid: true},
	}
	database := models.Database{User: "user", Address: "address", Password: "password"}
	emailApiKey := "dummy-api-key"

	return NewDefaultConfigService(realm, database, emailApiKey)
}
