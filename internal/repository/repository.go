package repository

import (
	"database/sql"
	"net/http"

	"github.com/agusespa/autz/internal/httperrors"
	"github.com/agusespa/autz/internal/models"
	"github.com/go-sql-driver/mysql"
)

type AuthRepository struct {
	DB *sql.DB
}

func NewAuthRepository(db *sql.DB) *AuthRepository {
	return &AuthRepository{DB: db}
}

func (repo *AuthRepository) CreateUser(uuid string, email string, passwordHash string) (int64, error) {
	result, err := repo.DB.Exec("INSERT INTO user_auth (user_uuid, email, password_hash) VALUES (?, ?, ?)", uuid, email, passwordHash)
	if err != nil {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 {
			error := httperrors.NewError(err, http.StatusConflict)
			return 0, error
		}
		error := httperrors.NewError(err, http.StatusInternalServerError)
		return 0, error
	}

	id, err := result.LastInsertId()
	if err != nil {
		error := httperrors.NewError(err, http.StatusInternalServerError)
		return 0, error
	}

	return id, nil
}

func (repo *AuthRepository) QueryUserByEmail(email string) (models.UserAuthEntity, error) {
	var user models.UserAuthEntity
	row := repo.DB.QueryRow("SELECT * FROM user_auth WHERE email=?", email)
	if err := row.Scan(&user.UserID, &user.UserUUID, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			err := httperrors.NewError(err, http.StatusNotFound)
			return user, err
		}
		err := httperrors.NewError(err, http.StatusInternalServerError)
		return user, err
	}
	return user, nil
}
