package repository

import (
	"database/sql"
	"net/http"

	"github.com/agusespa/a3n/internal/httperrors"
	"github.com/agusespa/a3n/internal/models"
	"github.com/lib/pq"
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

	var userID int64
	err := repo.DB.QueryRow(`
		INSERT INTO users (user_uuid, first_name, middle_name, last_name, email, password_hash)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING user_id
	`, uuid, body.FirstName, middleName, body.LastName, body.Email, passwordHash).Scan(&userID)

	if err != nil {
		if sqlErr, ok := err.(*pq.Error); ok && sqlErr.Code == "23505" {
			err := httperrors.NewError(err, http.StatusConflict)
			return 0, err
		}
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return 0, err
	}

	return userID, nil
}

func (repo *AuthRepository) ReadUserByEmail(email string) (models.UserAuthEntity, error) {
	var user models.UserAuthEntity

	row := repo.DB.QueryRow("SELECT * FROM users WHERE email=$1", email)
	err := row.Scan(&user.UserID, &user.UserUUID, &user.FirstName, &user.MiddleName, &user.LastName, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			err := httperrors.NewError(err, http.StatusNotFound)
			return user, err
		}
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return user, err
	}

	return user, nil
}

func (repo *AuthRepository) ReadUserById(userID int64) (models.UserAuthEntity, error) {
	var user models.UserAuthEntity

	row := repo.DB.QueryRow("SELECT * FROM users WHERE user_id=$1", userID)
	err := row.Scan(&user.UserID, &user.UserUUID, &user.FirstName, &user.MiddleName, &user.LastName, &user.Email, &user.PasswordHash, &user.EmailVerified, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			err := httperrors.NewError(err, http.StatusNotFound)
			return user, err
		}
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return user, err
	}

	return user, nil
}

func (repo *AuthRepository) UpdateUserEmailVerification(email string) error {
	result, err := repo.DB.Exec("UPDATE users SET email_verified = $1 WHERE email = $2", true, email)
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
	result, err := repo.DB.Exec("UPDATE users SET email = $1 WHERE user_id = $2", email, userID)
	if err != nil {
		if sqlErr, ok := err.(*pq.Error); ok && sqlErr.Code == "23505" {
			err = httperrors.NewError(err, http.StatusConflict)
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
		err := httperrors.NewError(err, http.StatusBadRequest)
		return 0, err
	}

	return userID, nil
}

func (repo *AuthRepository) UpdateUserPassword(userID int64, hashedPassword *[]byte) (int64, error) {
	result, err := repo.DB.Exec("UPDATE users SET password_hash = $1 WHERE user_id = $2", *hashedPassword, userID)
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
      WHERE tokens.token_hash = $1 
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
	_, err := repo.DB.Exec("INSERT INTO tokens (token_hash, user_id) VALUES ($1, $2)", tokenHash, userID)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return err
	}
	return nil
}

func (repo *AuthRepository) DeleteTokenByHash(tokenHash []byte) error {
	_, err := repo.DB.Exec("DELETE FROM tokens WHERE token_hash = $1", tokenHash)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return err
	}
	return nil
}

func (repo *AuthRepository) DeleteAllTokensByUserId(userID int64) error {
	_, err := repo.DB.Exec("DELETE FROM tokens WHERE user_id = $1", userID)
	if err != nil {
		err = httperrors.NewError(err, http.StatusInternalServerError)
		return err
	}
	return nil
}
