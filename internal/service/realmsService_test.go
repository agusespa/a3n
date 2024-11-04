package service

import (
	"testing"

	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/mocks"
	logger "github.com/agusespa/flogg/testing"
)

func setupRealmService() *DefaultRealmService {
	return &DefaultRealmService{
		AuthRepo: mocks.NewMockAuthRepository(),
		Config:   mocks.NewMockConfigService(),
		Logger:   &logger.MockLogger{},
	}
}

func TestGetRealmByIdWithValidId(t *testing.T) {
	rs := setupRealmService()

	realm, err := rs.GetRealmById(1)
	if err != nil {
		t.Errorf("failed to get realm by valid id: %s", err)
	}

	expectedName := "browser"
	if realm.RealmName != expectedName {
		t.Errorf("Expected RealmName to be '%s', got '%s'", expectedName, realm.RealmName)
	}
	expectedDomain := "localhost:9001"
	if realm.RealmDomain != expectedDomain {
		t.Errorf("Expected RealmDomain to be '%s', got '%s'", expectedDomain, realm.RealmDomain)
	}
}

func TestGetRealmByIdWithInvalidId(t *testing.T) {
	rs := setupRealmService()

	_, err := rs.GetRealmById(0)
	if err == nil {
		t.Fatalf("Expected an error, got nil")
	}
}

func TestGetRealmByIdWithInvalidData(t *testing.T) {
	rs := setupRealmService()

	_, err := rs.GetRealmById(2)

	if err == nil {
		t.Fatalf("Expected an error, got nil")
	}

	expectedMessage := "RealmName cannot be empty"
	if err.Error() != expectedMessage {
		t.Errorf("Expected error message to be '%s', got '%s'", expectedMessage, err.Error())
	}
}

func TestPutRealm(t *testing.T) {
	baseReq := models.RealmRequest{
		RealmName:     "Valid Realm",
		RealmDomain:   "valid.com",
		RefreshExp:    "3600",
		AccessExp:     "1800",
		EmailVerify:   "on",
		EmailAddr:     "valid@example.com",
		EmailProvider: "provider2",
		EmailSender:   "noreply@valid.com",
	}

	rs := setupRealmService()

	t.Run("Success: Valid Input", func(t *testing.T) {
		req := baseReq

		err := rs.PutRealm(req)
		if err != nil {
			t.Errorf("Expected no error, got error %s", err)
		}
	})

	t.Run("Failure: Invalid Email Address", func(t *testing.T) {
		req := baseReq
		req.EmailAddr = "invalid-email"

		err := rs.PutRealm(req)
		if err == nil {
			t.Fatalf("Expected an error, got nil")
		}
	})

	t.Run("Failure: Invalid Refresh Expiration Value", func(t *testing.T) {
		req := baseReq
		req.RefreshExp = "invalid"

		err := rs.PutRealm(req)
		if err == nil {
			t.Fatalf("Expected an error, got nil")
		}
	})

	t.Run("Failure: Invalid Access Expiration Value", func(t *testing.T) {
		req := baseReq
		req.AccessExp = "invalid"

		err := rs.PutRealm(req)
		if err == nil {
			t.Fatalf("Expected an error, got nil")
		}
	})

	t.Run("Failure: Incomplete Email Configuration with Verification On", func(t *testing.T) {
		req := baseReq
		req.EmailProvider = ""

		err := rs.PutRealm(req)
		if err == nil {
			t.Fatalf("Expected an error, got nil")
		}
	})

	t.Run("Failure: Unsupported Email Provider", func(t *testing.T) {
		req := baseReq
		req.EmailProvider = "unsupported-provider"

		err := rs.PutRealm(req)
		if err == nil {
			t.Fatalf("Expected an error, got nil")
		}
	})

	t.Run("Success: Optional Email Fields", func(t *testing.T) {
		req := baseReq
		req.EmailAddr = ""
		req.EmailProvider = ""
		req.EmailSender = ""
		req.EmailVerify = "off"

		err := rs.PutRealm(req)
		if err != nil {
			t.Errorf("Expected no error, got error %s", err)
		}
	})
}
