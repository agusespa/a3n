package database

import (
	"database/sql"
	"log"

	"github.com/go-sql-driver/mysql"
)

func ConnectDB() (*sql.DB, error) {
	cfg := mysql.Config{
		User:      "root",
		Passwd:    "sg46sg46",
		Net:       "tcp",
		Addr:      "localhost:3306",
		DBName:    "auth",
		ParseTime: true,
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatalf("Error opening database connection: %v", err)
	}

	pingErr := db.Ping()
	if pingErr != nil {
		log.Fatalf("Error pinging database: %v", pingErr)
	}

	return db, nil
}
