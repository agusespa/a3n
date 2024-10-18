package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/agusespa/a3n/internal/helpers"
	"github.com/agusespa/a3n/internal/service"
	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	dbUser, dbAddr, dbPassword, err := helpers.GetDatabaseVars()
	if err != nil {
		log.Fatal(fmt.Errorf("failed to get database variables: %s", err.Error()))
	}
	cfg := mysql.Config{
		User:   dbUser,
		Passwd: dbPassword,
		Net:    "tcp",
		Addr:   dbAddr,
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal(fmt.Errorf("failed to establish database connection: %s", err.Error()))
	}

	defer db.Close()

	dbName := "a3n"

	if _, err := db.Exec("CREATE DATABASE IF NOT EXISTS " + dbName); err != nil {
		log.Fatal(err)
	}

	if _, err := db.Exec("USE " + dbName); err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS realms (
			realm_id INT AUTO_INCREMENT PRIMARY KEY,
			realm_name VARCHAR(20) NOT NULL UNIQUE,
			realm_domain VARCHAR(100) NOT NULL DEFAULT "localhost:9001",
			refresh_exp INT NOT NULL DEFAULT 1440,
			access_exp INT NOT NULL DEFAULT 5,
			email_verify BOOLEAN DEFAULT FALSE,
			email_provider VARCHAR(36),
			email_sender VARCHAR(36),
			email_addr VARCHAR(100),
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Realms table ensured")

	_, err = db.Exec("INSERT IGNORE INTO realms (realm_name) VALUES ('default')")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Default realm ensured")

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			user_id INT AUTO_INCREMENT PRIMARY KEY,
			user_uuid VARCHAR(36) NOT NULL UNIQUE,
			first_name VARCHAR(20) NOT NULL,
			middle_name VARCHAR(20),
			last_name VARCHAR(30) NOT NULL,
			email VARCHAR(100) NOT NULL UNIQUE,
			password_hash BINARY(64) NOT NULL,
			email_verified BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Users table ensured")

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS tokens (
			token_id INT AUTO_INCREMENT PRIMARY KEY,
			token_hash BINARY(32) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP,
			user_id INT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Tokens table ensured")

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS roles (
			role_id INT AUTO_INCREMENT PRIMARY KEY,
			role_name VARCHAR(36) NOT NULL UNIQUE
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Roles table ensured")

	_, err = db.Exec("INSERT IGNORE INTO roles (role_name) VALUES ('admin')")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Admin role ensured")

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS user_roles (
			user_id INTEGER,
			role_id INTEGER,
			PRIMARY KEY (user_id, role_id),
			FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
			FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("User_roles table ensured")

	var adminUserCount int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM users u
		JOIN user_roles ur ON u.user_id = ur.user_id
		JOIN roles r ON ur.role_id = r.role_id
		WHERE r.role_name = 'admin'
	`).Scan(&adminUserCount)
	if err != nil {
		log.Fatal(err)
	}

	if adminUserCount == 0 {
		reader := bufio.NewReader(os.Stdin)

		fmt.Println("\nLet's create an admin user.")
		fmt.Print("Enter first name: ")
		firstName, _ := reader.ReadString('\n')
		firstName = strings.TrimSpace(firstName)

		fmt.Print("Enter middle name (press Enter if none): ")
		middleName, _ := reader.ReadString('\n')
		middleName = strings.TrimSpace(middleName)

		fmt.Print("Enter last name: ")
		lastName, _ := reader.ReadString('\n')
		lastName = strings.TrimSpace(lastName)

		fmt.Print("Enter email: ")
		email, _ := reader.ReadString('\n')
		email = strings.TrimSpace(email)
		if !service.IsValidEmail(email) {
			log.Fatal("not a valid email address")
		}

		fmt.Print("Enter password: ")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)
		if !service.IsValidPassword(password) {
			log.Fatal("password doesn't meet minimum criteria")
		}

		userUUID := uuid.New().String()

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}

		result, err := db.Exec(`
		INSERT INTO users (user_uuid, first_name, middle_name, last_name, email, password_hash, email_verified)
		VALUES (?, ?, ?, ?, ?, ?, true)`, userUUID, firstName, middleName, lastName, email, passwordHash)
		if err != nil {
			log.Fatal(err)
		}

		userID, _ := result.LastInsertId()

		_, err = db.Exec(`
		INSERT INTO user_roles (user_id, role_id)
		SELECT ?, role_id FROM roles WHERE role_name = 'admin'`, userID)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Admin user created successfully")
	}

	fmt.Println("\nDatabase setup completed successfully")
}
