package database

import (
	"database/sql"

	"github.com/agusespa/a3n/internal/models"
	"github.com/go-sql-driver/mysql"
)

func ConnectDB(config models.ApiConfig, password string) (*sql.DB, error) {
	cfg := mysql.Config{
		User:      config.Database.User,
		Passwd:    password,
		Net:       "tcp",
		Addr:      config.Database.Address,
		DBName:    config.Database.Name,
		ParseTime: true,
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}
