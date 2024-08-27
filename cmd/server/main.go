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

func corsMiddleware(next http.Handler, domain string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", domain)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
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

	authRepository := repository.NewMySqlRepository(db)

	emailService := service.NewDefaultEmailService(config, emailApiKey, logg)

	authService := service.NewDefaultAuthService(authRepository, config.Api, emailService, encryptionKey, logg)

	authHandler := handlers.NewDefaultAuthHandler(authService, logg)

	mux := http.NewServeMux()
	mux.HandleFunc("/authapi/register", authHandler.HandleUserRegister)
	mux.HandleFunc("/authapi/login", authHandler.HandleUserLogin)
	mux.HandleFunc("/authapi/user/email/verify", authHandler.HandleUserEmailVerification)
	mux.HandleFunc("/authapi/user/email", authHandler.HandleUserEmailChange)
	mux.HandleFunc("/authapi/user/password", authHandler.HandleUserPasswordChange)
	mux.HandleFunc("/authapi/user", authHandler.HandleUserData)
	mux.HandleFunc("/authapi/authenticate", authHandler.HandleUserAuthentication)
	mux.HandleFunc("/authapi/refresh", authHandler.HandleTokenRefresh)
	mux.HandleFunc("/authapi/logout/all", authHandler.HandleAllUserTokensRevocation)
	mux.HandleFunc("/authapi/logout", authHandler.HandleTokenRevocation)

	port := os.Getenv("A3N_PORT")
	if port == "" {
		port = "3001"
	}

	logg.LogInfo(fmt.Sprintf("Listening on port %v", port))

	err = http.ListenAndServe(":"+port, corsMiddleware(mux, config.Api.Client.Domain))
	if err != nil {
		logg.LogFatal(fmt.Errorf("failed to start HTTP server: %s", err.Error()))
	}
}
