package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/agusespa/a3n/internal/database"
	"github.com/agusespa/a3n/internal/handlers"
	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/repository"
	"github.com/agusespa/a3n/internal/service"
)

func init() {
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}
	var config models.Config
	err = json.Unmarshal(configFile, &config)
	if err != nil {
		log.Fatalf("Error parsing config file: %v", err)
		return
	}

	encryptionKey := os.Getenv("A3N_ENCRYPTION_KEY")
	if encryptionKey == "" {
		log.Fatal("Error getting ENCRYPTION_KEY variable")
	}
	dbPassword := os.Getenv("A3N_DB_PASSWORD")
	if dbPassword == "" {
		log.Fatal("Error getting DB_PASSWORD variable")
	}
	emailApiKey := os.Getenv("A3N_EMAIL_API_KEY")
	if emailApiKey == "" {
		log.Fatal("Error getting EMAIL_API_KEY variable")
	}

	db, err := database.ConnectDB(config, dbPassword)
	if err != nil {
		log.Fatalf("Error establishing database connection: %v", err)
	}

	authRepository := repository.NewAuthRepository(db)

	emailService := service.NewEmailService(config, emailApiKey)

	authService := service.NewAuthService(authRepository, config, emailService, encryptionKey)

	authHandler := handlers.NewAuthHandler(authService)

	http.HandleFunc("/authapi/register", authHandler.HandleUserRegister)
	http.HandleFunc("/authapi/login", authHandler.HandleUserLogin)
	http.HandleFunc("/authapi/user/email/verify", authHandler.HandleUserEmailVerification)
	http.HandleFunc("/authapi/user/email", authHandler.HandleUserEmailChange)
	http.HandleFunc("/authapi/user/password", authHandler.HandleUserPasswordChange)
	http.HandleFunc("/authapi/authenticate", authHandler.HandleUserAuthentication)
	http.HandleFunc("/authapi/refresh", authHandler.HandleTokenRefresh)
	http.HandleFunc("/authapi/logout/all", authHandler.HandleUserTokensRevocation)
	http.HandleFunc("/authapi/logout", authHandler.HandleTokenRevocation)
}

func main() {
	port := os.Getenv("A3N_PORT")
	if port == "" {
		port = "3001"
	}
	log.Printf("Listening on port %v", port)

	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatalf("Error starting the HTTP server: %v", err)
	}
}
