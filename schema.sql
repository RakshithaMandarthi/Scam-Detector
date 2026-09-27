-- Scam Detector database schema (MySQL 8 / MariaDB 10.4+)
-- Run once:  mysql -u root -p < schema.sql

CREATE DATABASE IF NOT EXISTS scam_detector
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE scam_detector;

-- Registered users. password_hash is NULL for accounts that only use Google sign-in.
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username      VARCHAR(20)  NOT NULL,
  email         VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NULL,
  google_id     VARCHAR(64)  NULL,
  created_at    DATETIME     NOT NULL,          -- UTC
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_username (username),      -- case-insensitive because of the collation
  UNIQUE KEY uq_users_email (email),
  UNIQUE KEY uq_users_google (google_id)
) ENGINE=InnoDB;

-- One row per analyzed message (powers History and Dashboard).
CREATE TABLE IF NOT EXISTS analyses (
  id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id    INT UNSIGNED NOT NULL,
  message    TEXT         NOT NULL,
  risk_score TINYINT UNSIGNED NOT NULL,         -- 0-100
  verdict    ENUM('safe','suspicious','scam') NOT NULL,
  reasons    TEXT         NOT NULL,             -- JSON: [{key, weight, params}]
  created_at DATETIME     NOT NULL,             -- UTC
  PRIMARY KEY (id),
  KEY idx_analyses_user_time (user_id, created_at),
  CONSTRAINT fk_analyses_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Password-reset tokens. Only a SHA-256 hash of the token is stored.
CREATE TABLE IF NOT EXISTS password_resets (
  id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id    INT UNSIGNED NOT NULL,
  token_hash CHAR(64)     NOT NULL,
  expires_at DATETIME     NOT NULL,             -- UTC
  PRIMARY KEY (id),
  UNIQUE KEY uq_reset_token (token_hash),
  CONSTRAINT fk_reset_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB;
