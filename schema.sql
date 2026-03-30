-- ============================================================
-- PhishGuard - MySQL 8.0 Database Schema
-- Run this script once to set up the phishguard database.
-- Usage: mysql -u root -p < schema.sql
-- ============================================================

CREATE DATABASE IF NOT EXISTS phishguard
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE phishguard;

-- ============================================================
-- TABLE: incidents
-- Stores every URL analysis result for forensic investigation.
-- ============================================================
CREATE TABLE IF NOT EXISTS incidents (
    id                      INT AUTO_INCREMENT PRIMARY KEY,
    timestamp               DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    email_sender            VARCHAR(255),
    email_subject           VARCHAR(512),
    url_found               TEXT NOT NULL,
    sender_score            DOUBLE DEFAULT 0.0,
    text_score              DOUBLE DEFAULT 0.0,
    ai_model_score          DOUBLE DEFAULT 0.0,
    threat_intel_score      DOUBLE DEFAULT 0.0,
    visual_score            DOUBLE DEFAULT 0.0,
    final_risk_score        DOUBLE NOT NULL DEFAULT 0.0,
    ai_decision             ENUM('SAFE', 'SUSPICIOUS', 'HIGH_RISK') NOT NULL,
    phishtank_confirmed     BOOLEAN DEFAULT FALSE,
    virustotal_detections   INT DEFAULT 0,
    visual_brand_detected   VARCHAR(100),
    action_taken            ENUM('ALLOWED', 'WARNED', 'BLOCKED') NOT NULL,
    INDEX idx_timestamp     (timestamp),
    INDEX idx_ai_decision   (ai_decision),
    INDEX idx_final_score   (final_risk_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE: quarantine
-- Blocked domains — prevents repeated analysis of known bad actors.
-- ============================================================
CREATE TABLE IF NOT EXISTS quarantine (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    domain          VARCHAR(255) NOT NULL UNIQUE,
    date_added      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason          TEXT,
    times_blocked   INT DEFAULT 1,
    last_attempt    DATETIME,
    INDEX idx_domain (domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE: logs
-- Application event log for debugging and audit trail.
-- ============================================================
CREATE TABLE IF NOT EXISTS logs (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    event_time  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type  VARCHAR(100) NOT NULL,
    severity    ENUM('INFO', 'WARNING', 'ERROR', 'CRITICAL') NOT NULL DEFAULT 'INFO',
    details     TEXT,
    INDEX idx_event_time (event_time),
    INDEX idx_severity   (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- TABLE: daily_stats
-- Aggregated daily metrics used by the Dashboard charts.
-- ============================================================
CREATE TABLE IF NOT EXISTS daily_stats (
    stat_date               DATE NOT NULL PRIMARY KEY,
    total_emails_scanned    INT DEFAULT 0,
    total_urls_checked      INT DEFAULT 0,
    threats_detected        INT DEFAULT 0,
    threats_blocked         INT DEFAULT 0,
    average_risk_score      DOUBLE DEFAULT 0.0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Seed: Insert a startup log entry to verify schema works.
-- ============================================================
INSERT INTO logs (event_type, severity, details)
VALUES ('SYSTEM_STARTUP', 'INFO', 'PhishGuard database schema initialized successfully.');
