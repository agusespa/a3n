CREATE DATABASE autz;

USE autz;

CREATE TABLE users (
user_id INT AUTO_INCREMENT PRIMARY KEY,
user_uuid VARCHAR(36) NOT NULL UNIQUE,
email VARCHAR(100) NOT NULL UNIQUE,
password_hash BINARY(64) NOT NULL,
email_verified BOOLEAN DEFAULT FALSE,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tokens (
token_id INT AUTO_INCREMENT PRIMARY KEY,
token_hash BINARY(32) NOT NULL,
user_id INT NOT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
expires_at TIMESTAMP,
CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
