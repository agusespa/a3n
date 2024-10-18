package helpers

import (
	"errors"
	"os"
)

func GetApiKeyVars() (string, string, error) {
	encryptionKey := os.Getenv("A3N_ENCRYPTION_KEY")
	if encryptionKey == "" {
		return "", "", errors.New("failed to get ENCRYPTION_KEY variable")
	}
	emailApiKey := os.Getenv("A3N_EMAIL_API_KEY")
	if emailApiKey == "" {
		return "", "", errors.New("failed to get EMAIL_API_KEY variable")
	}
	return encryptionKey, emailApiKey, nil
}

func GetDatabaseVars() (string, string, string, error) {
	dbUser := os.Getenv("A3N_DB_USER")
	if dbUser == "" {
		return "", "", "", errors.New("failed to get A3N_DB_USER variable")
	}
	dbAddr := os.Getenv("A3N_DB_ADDR")
	if dbAddr == "" {
		return "", "", "", errors.New("failed to get A3N_DB_ADDR variable")
	}
	dbPassword := os.Getenv("A3N_DB_PASSWORD")
	if dbPassword == "" {
		return "", "", "", errors.New("failed to get A3N_DB_PASSWORD variable")
	}
	return dbUser, dbAddr, dbPassword, nil
}
