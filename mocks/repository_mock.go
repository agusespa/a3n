package mocks

import (
	"errors"
	"net/http"
	"time"

	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/models"
)

type MockAuthRepository struct{}

func NewMockAuthRepository() *MockAuthRepository {
	return &MockAuthRepository{}
}

var mockUser = models.UserAuthEntity{
	UserID:        1,
	UserUUID:      "test-uuid",
	FirstName:     "John",
	LastName:      "Doe",
	Email:         "john@example.com",
	PasswordHash:  []byte("hashed_password"),
	EmailVerified: false,
	CreatedAt:     time.Now(),
}

func (m *MockAuthRepository) CreateUser(uuid string, body models.UserRequest, passwordHash []byte) (int64, error) {
	return 1, nil
}

func (m *MockAuthRepository) ReadUserByEmail(email string) (models.UserAuthEntity, error) {
	if email == mockUser.Email {
		return mockUser, nil
	}
	return models.UserAuthEntity{}, httperrors.NewError(errors.New("user not found"), http.StatusNotFound)
}

func (m *MockAuthRepository) ReadUserById(userID int64) (models.UserAuthEntity, error) {
	if userID == mockUser.UserID {
		return mockUser, nil
	}
	return models.UserAuthEntity{}, httperrors.NewError(errors.New("user not found"), http.StatusNotFound)
}

func (m *MockAuthRepository) UpdateUserEmailVerification(email string) error {
	if email == mockUser.Email {
		return nil
	}
	return httperrors.NewError(errors.New("user not found"), http.StatusBadRequest)
}

func (m *MockAuthRepository) UpdateUserEmail(userID int64, email string) (int64, error) {
	if userID == mockUser.UserID {
		return userID, nil
	}
	return 0, httperrors.NewError(errors.New("user not found"), http.StatusBadRequest)
}

func (m *MockAuthRepository) UpdateUserPassword(userID int64, hashedPassword *[]byte) (int64, error) {
	if userID == mockUser.UserID {
		return userID, nil
	}
	return 0, httperrors.NewError(errors.New("user not found"), http.StatusBadRequest)
}

func (m *MockAuthRepository) ReadUserByToken(tokenHash []byte) (models.UserAuthEntity, error) {
	if string(tokenHash) == "valid_token_hash" {
		return mockUser, nil
	}
	return models.UserAuthEntity{}, httperrors.NewError(errors.New("token not found"), http.StatusNotFound)
}

func (m *MockAuthRepository) CreateRefreshToken(userID int64, tokenHash []byte) error {
	return nil
}

func (m *MockAuthRepository) DeleteTokenByHash(tokenHash []byte) error {
	return nil
}

func (m *MockAuthRepository) DeleteAllTokensByUserId(userID int64) error {
	return nil
}
