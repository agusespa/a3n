package service

import (
	"testing"

	"github.com/agusespa/a3n/mocks"
)

func TestReadRealmByIdWithValidId(t *testing.T) {
	rs := &DefaultRealmService{
		AuthRepo: mocks.NewMockAuthRepository(),
	}

	realm, err := rs.AuthRepo.ReadRealmById(1)
	if err != nil {
		t.Errorf("failed to read realm by valid id: %s", err)
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

func TestReadRealmByIdWithInvalidId(t *testing.T) {
	rs := &DefaultRealmService{
		AuthRepo: mocks.NewMockAuthRepository(),
	}

	_, err := rs.AuthRepo.ReadRealmById(0)
	if err == nil {
		t.Errorf("failed to return error due to invalid id")
	}
}
