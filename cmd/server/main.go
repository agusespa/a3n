package main

import (
	"log"
	"net/http"

	"github.com/agusespa/ecom-be/auth/internal/database"
	"github.com/agusespa/ecom-be/auth/internal/handlers"
	"github.com/agusespa/ecom-be/auth/internal/repository"
	"github.com/agusespa/ecom-be/auth/internal/service"
)

func main() {
	db, dbErr := database.ConnectDB()
	if dbErr != nil {
		log.Fatalf("Error establishing database connection: %v", dbErr)
	}

	// TODO: get port dinamically
	port := "3001"

	authRepository := repository.NewAuthRepository(db)
	authService := service.NewProductService(authRepository)
	authHandler := handlers.NewAuthHandler(authService)

	http.HandleFunc("/authapi/register", authHandler.HandleUserRegister)
	http.HandleFunc("/authapi/login", authHandler.HandleUserLogin)
	http.HandleFunc("/authapi/refresh", authHandler.HandleTokenRefresh)

	log.Printf("Listening on port %v", port)
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatalf("Error starting the HTTP server: %v", err)
	}
}
