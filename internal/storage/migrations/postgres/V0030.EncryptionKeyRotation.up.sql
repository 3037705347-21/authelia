CREATE TABLE IF NOT EXISTS encryption_key_rotation (
    id SERIAL CONSTRAINT encryption_key_rotation_pkey PRIMARY KEY,
    key_fingerprint CHAR(64) NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    rows_total INTEGER NOT NULL DEFAULT 0,
    checksum CHAR(64) NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX encryption_key_rotation_fingerprint_table_key ON encryption_key_rotation (key_fingerprint, table_name);
