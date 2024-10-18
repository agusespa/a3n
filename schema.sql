CREATE DATABASE a3n;

USE a3n;

CREATE TABLE realms (
    realm_id INT AUTO_INCREMENT PRIMARY KEY,
    realm_name VARCHAR(20) NOT NULL UNIQUE,
    realm_domain VARCHAR(100) NOT NULL DEFAULT "localhost:9001",
    refresh_exp INT NOT NULL DEFAULT 1440,
    access_exp INT NOT NULL DEFAULT 5,
    email_verify BOOLEAN DEFAULT FALSE,
    email_provider VARCHAR(36),
    email_sender VARCHAR(36),
    email_addr VARCHAR(100),
);

CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    user_uuid VARCHAR(36) NOT NULL UNIQUE,
    first_name VARCHAR(20) NOT NULL,
    middle_name VARCHAR(20),
    last_name VARCHAR(30) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash BINARY(64) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tokens (
    token_id INT AUTO_INCREMENT PRIMARY KEY,
    token_hash BINARY(32) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE roles (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(36) NOT NULL UNIQUE,
)

CREATE TABLE user_roles (
    user_id INTEGER,
    role_id INTEGER,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE
);
