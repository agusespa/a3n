package database

import (
	"database/sql"
	"fmt"

	"github.com/agusespa/a3n/internal/models"
	_ "github.com/lib/pq"
)

func ConnectDB(config models.Database, password string) (*sql.DB, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		config.Address,
		config.Port,
		config.User,
		password,
		config.Name,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}
