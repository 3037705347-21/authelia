CREATE TABLE IF NOT EXISTS encryption_key_rotation (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    key_fingerprint CHAR(64) NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    rows_total INTEGER NOT NULL DEFAULT 0,
    checksum CHAR(64) NOT NULL,
    completed_at DATETIME NOT NULL,
    UNIQUE (key_fingerprint, table_name)
);
