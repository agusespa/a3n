package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/agusespa/a3n/internal/database"
	"github.com/agusespa/a3n/internal/handlers"
	"github.com/agusespa/a3n/internal/logger"
	"github.com/agusespa/a3n/internal/models"
	"github.com/agusespa/a3n/internal/repository"
	"github.com/agusespa/a3n/internal/service"
)

var logg logger.Logger

func init() {
	var devFlag bool
	flag.BoolVar(&devFlag, "dev", false, "enable development mode")
	flag.Parse()
	logg = logger.NewLogger(devFlag)

	encryptionKey := os.Getenv("A3N_ENCRYPTION_KEY")
	if encryptionKey == "" {
		logg.LogFatal(errors.New("failed to get ENCRYPTION_KEY variable"))
	}
	dbPassword := os.Getenv("A3N_DB_PASSWORD")
	if dbPassword == "" {
		logg.LogFatal(errors.New("failed to get DB_PASSWORD variable"))
	}
	emailApiKey := os.Getenv("A3N_EMAIL_API_KEY")
	if emailApiKey == "" {
		logg.LogFatal(errors.New("failed to get EMAIL_API_KEY variable"))
	}

	configFile, err := os.ReadFile("config/config.json")
	if err != nil {
		logg.LogFatal(err)
	}
	var config models.Config
	err = json.Unmarshal(configFile, &config)
	if err != nil {
		logg.LogFatal(err)
	}

	db, err := database.ConnectDB(config.Api.Database, dbPassword)
	if err != nil {
		logg.LogFatal(fmt.Errorf("failed to establish database connection: %s", err.Error()))
	}

	authRepository := repository.NewAuthRepository(db)

	emailService := service.NewEmailService(config, emailApiKey, logg)

	authService := service.NewAuthService(authRepository, config.Api, emailService, encryptionKey, logg)

	authHandler := handlers.NewAuthHandler(authService, logg)

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

	logg.LogInfo(fmt.Sprintf("Listening on port %v", port))

	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		logg.LogFatal(fmt.Errorf("failed to start HTTP server: %s", err.Error()))
	}
}
