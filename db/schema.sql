-- MikroTik CPE DNS Doctor - DB Schema (aligned with core/db_manager.py)
-- Charset: utf8mb4
-- Notes:
-- - Safe to run multiple times (uses IF NOT EXISTS).

CREATE TABLE IF NOT EXISTS scan_sessions (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  status VARCHAR(32) NOT NULL DEFAULT 'running',
  mode VARCHAR(32) NOT NULL,
  city VARCHAR(64) NULL,
  total_cpes INT NOT NULL DEFAULT 0,
  started_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  finished_at DATETIME(3) NULL DEFAULT NULL,
  meta_json JSON NULL,
  PRIMARY KEY (id),
  KEY idx_scan_sessions_started_at (started_at),
  KEY idx_scan_sessions_status (status),
  KEY idx_scan_sessions_city (city)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS rules (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  check_command TEXT NOT NULL,
  warning_regex TEXT NOT NULL,
  fix_command TEXT NOT NULL,
  priority INT NOT NULL DEFAULT 100,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_rules_active_priority (is_active, priority)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS cpe_inventory (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  last_ip VARCHAR(45) NOT NULL,
  pppoe_username VARCHAR(128) NULL,
  last_city VARCHAR(64) NULL,
  last_login_success TINYINT(1) NULL,
  last_password_used VARCHAR(255) NULL,
  last_password_is_empty TINYINT(1) NULL,
  last_status VARCHAR(64) NULL,
  last_fix_applied TINYINT(1) NULL,
  last_warning_count INT NOT NULL DEFAULT 0,
  last_session_id BIGINT UNSIGNED NULL,
  last_seen_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  summary_json JSON NULL,
  warnings_json JSON NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_cpe_inventory_user (pppoe_username),
  KEY idx_cpe_inventory_city (last_city),
  KEY idx_cpe_inventory_last_seen (last_seen_at),
  KEY idx_cpe_inventory_session (last_session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  session_id BIGINT UNSIGNED NOT NULL,
  cpe_id BIGINT UNSIGNED NULL,
  ip VARCHAR(45) NOT NULL,
  action VARCHAR(32) NOT NULL,
  status VARCHAR(64) NOT NULL,
  login_success TINYINT(1) NULL,
  password_used VARCHAR(255) NULL,
  password_is_empty TINYINT(1) NULL,
  warning_count INT NOT NULL DEFAULT 0,
  fix_applied TINYINT(1) NULL,
  rebooted TINYINT(1) NULL,
  rules_result_json JSON NULL,
  raw_output_text MEDIUMTEXT NULL,
  pppoe_username VARCHAR(128) NULL,
  city VARCHAR(64) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  UNIQUE KEY uq_logs_session_ip_action (session_id, ip, action),
  KEY idx_logs_ip_created (ip, created_at),
  KEY idx_logs_session (session_id),
  KEY idx_logs_status (status),
  KEY idx_logs_user_created (pppoe_username, created_at),
  KEY idx_logs_city_created (city, created_at),
  KEY idx_logs_cpe_created (cpe_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
