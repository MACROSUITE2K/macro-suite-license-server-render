CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key VARCHAR(128) NOT NULL UNIQUE,
    license_key_plain VARCHAR(32) NULL,
    license_key_suffix VARCHAR(4) NULL,
    product VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('active', 'revoked', 'suspended')),
    max_devices INTEGER NOT NULL,
    expiration_date DATE NULL,
    flagged_reason VARCHAR(255) NULL,
    flagged_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_licenses_license_key ON licenses (license_key);

CREATE TABLE IF NOT EXISTS activations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id INTEGER NOT NULL,
    device_id VARCHAR(128) NOT NULL,
    device_name VARCHAR(128) NOT NULL,
    device_fingerprint VARCHAR(64) NULL,
    ip_address VARCHAR(45) NULL,
    activated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat_at TIMESTAMP NULL,
    heartbeat_failures INTEGER NOT NULL DEFAULT 0,
    ip_change_count INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT fk_activations_license FOREIGN KEY (license_id) REFERENCES licenses (id) ON DELETE CASCADE,
    CONSTRAINT uq_activation_license_device UNIQUE (license_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_activations_license_id ON activations (license_id);
CREATE INDEX IF NOT EXISTS idx_activations_last_heartbeat_at ON activations (last_heartbeat_at);

CREATE TABLE IF NOT EXISTS challenge_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_id VARCHAR(64) NOT NULL UNIQUE,
    license_id INTEGER NOT NULL,
    device_id VARCHAR(128) NOT NULL,
    device_fingerprint VARCHAR(64) NOT NULL,
    nonce VARCHAR(128) NOT NULL,
    ip_address VARCHAR(45) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    CONSTRAINT fk_challenge_license FOREIGN KEY (license_id) REFERENCES licenses (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_challenge_sessions_challenge_id ON challenge_sessions (challenge_id);
CREATE INDEX IF NOT EXISTS idx_challenge_sessions_expires_at ON challenge_sessions (expires_at);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    detail TEXT NOT NULL,
    ip_address VARCHAR(45) NULL,
    license_id INTEGER NULL,
    activation_id INTEGER NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_security_events_license FOREIGN KEY (license_id) REFERENCES licenses (id) ON DELETE SET NULL,
    CONSTRAINT fk_security_events_activation FOREIGN KEY (activation_id) REFERENCES activations (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events (event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events (created_at);
