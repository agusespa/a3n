package service

import (
	"testing"

	"github.com/agusespa/a3n/mocks"
)

func setupRealmService() *DefaultRealmService {
	return &DefaultRealmService{
		AuthRepo: mocks.NewMockAuthRepository(),
		Logger:   mocks.NewMockLogger(true),
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
