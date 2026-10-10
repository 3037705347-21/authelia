CREATE TABLE IF NOT EXISTS encryption_key_rotation (
    id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT,
    key_fingerprint CHAR(64) NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    rows_total INTEGER NOT NULL DEFAULT 0,
    checksum CHAR(64) NOT NULL,
    completed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY (key_fingerprint, table_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
