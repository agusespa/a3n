package repository

import (
	"database/sql"
	"net/http"

	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/models"
	"github.com/go-sql-driver/mysql"
)

type AuthRepository struct {
	DB *sql.DB
}

func NewAuthRepository(db *sql.DB) *AuthRepository {
	return &AuthRepository{DB: db}
}

func (repo *AuthRepository) CreateUser(uuid string, body models.UserRequest, passwordHash []byte) (int64, error) {
	var middleName *string
	if body.MiddleName == "" {
		middleName = nil
	} else {
		middleName = &body.MiddleName
	}

	result, err := repo.DB.Exec("INSERT INTO users (user_uuid, first_name, middle_name, last_name, email, password_hash) VALUES (?, ?, ?, ?, ?, ?)", uuid, body.FirstName, middleName, body.LastName, body.Email, passwordHash)
	if err != nil {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 {
			err = httperrors.NewError(err, http.StatusConflict)
			return 0, err
		}
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return 0, err
	}

	return id, nil
}

func (repo *AuthRepository) ReadUserByEmail(email string) (models.UserAuthEntity, error) {
	var user models.UserAuthEntity

	row := repo.DB.QueryRow("SELECT * FROM users WHERE email=?", email)
	err := row.Scan(&user.UserID, &user.UserUUID, &user.FirstName, &user.MiddleName, &user.LastName, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			err = httperrors.NewError(err, http.StatusNotFound)
			return user, err
		}
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return user, err
	}

	return user, nil
}

func (repo *AuthRepository) ReadUserById(userID int64) (models.UserAuthEntity, error) {
	var user models.UserAuthEntity

	row := repo.DB.QueryRow("SELECT * FROM users WHERE user_id=?", userID)
	err := row.Scan(&user.UserID, &user.UserUUID, &user.FirstName, &user.MiddleName, &user.LastName, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			err = httperrors.NewError(err, http.StatusNotFound)
			return user, err
		}
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return user, err
	}

	return user, nil
}

func (repo *AuthRepository) UpdateUserEmailVerification(email string) error {
	result, err := repo.DB.Exec("UPDATE users SET email_verified = ? WHERE email = ?", true, email)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return err
	}

	if rowsAffected == 0 {
		err = httperrors.NewError(err, http.StatusBadRequest)
		return err
	}

	return nil
}

func (repo *AuthRepository) UpdateUserEmail(userID int64, email string) (int64, error) {
	result, err := repo.DB.Exec("UPDATE users SET email = ? WHERE user_id = ?", email, userID)
	if err != nil {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1064 {
			err = httperrors.NewError(err, http.StatusBadRequest)
			return 0, err
		}
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return 0, err
	}

	if rowsAffected == 0 {
		err = httperrors.NewError(err, http.StatusBadRequest)
		return 0, err
	}

	return userID, nil
}

func (repo *AuthRepository) UpdateUserPassword(userID int64, hashedPassword *[]byte) (int64, error) {
	result, err := repo.DB.Exec("UPDATE users SET password_hash = ? WHERE user_id = ?", *hashedPassword, userID)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return 0, err
	}

	if rowsAffected == 0 {
		err = httperrors.NewError(err, http.StatusBadRequest)
		return 0, err
	}

	return userID, nil
}

func (repo *AuthRepository) ReadUserByToken(tokenHash []byte) (models.UserAuthEntity, error) {
	var user models.UserAuthEntity

	query := `
      SELECT users.* 
      FROM users 
      JOIN tokens ON users.user_id = tokens.user_id
      WHERE tokens.token_hash = ? 
  `
	row := repo.DB.QueryRow(query, tokenHash)
	err := row.Scan(&user.UserID, &user.UserUUID, &user.FirstName, &user.MiddleName, &user.LastName, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			err = httperrors.NewError(err, http.StatusNotFound)
			return user, err
		}
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return user, err
	}

	return user, nil
}

func (repo *AuthRepository) CreateRefreshToken(userID int64, tokenHash []byte) error {
	_, err := repo.DB.Exec("INSERT INTO tokens (token_hash, user_id) VALUES (?, ?)", tokenHash, userID)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return err
	}
	return nil
}

func (repo *AuthRepository) DeleteTokenByHash(tokenHash []byte) error {
	_, err := repo.DB.Exec("DELETE FROM tokens WHERE token_hash = ?", tokenHash)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return err
	}
	return nil
}

func (repo *AuthRepository) DeleteAllTokensByUserId(userID int64) error {
	_, err := repo.DB.Exec("DELETE FROM tokens WHERE user_id = ?", userID)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return err
	}
	return nil
}
