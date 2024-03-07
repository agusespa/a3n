package database

import (
	"database/sql"

	"github.com/go-sql-driver/mysql"
)

func ConnectDB() (*sql.DB, error) {
	cfg := mysql.Config{
		User:      "root",
		Passwd:    "sg46sg46",
		Net:       "tcp",
		Addr:      "localhost:3306",
		DBName:    "autz",
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
