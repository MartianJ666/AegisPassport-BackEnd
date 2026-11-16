CREATE TABLE external_identities (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    provider VARCHAR(40) NOT NULL,
    issuer VARCHAR(255) NOT NULL,
    provider_subject VARCHAR(255) NOT NULL,
    display_name VARCHAR(100),
    avatar VARCHAR(500),
    created_at DATETIME(6) NOT NULL,
    last_authenticated_at DATETIME(6),
    PRIMARY KEY (id),
    CONSTRAINT fk_external_identity_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT uk_external_identity_subject UNIQUE (provider, issuer, provider_subject)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_external_identity_user ON external_identities(user_id);

CREATE TABLE external_auth_transactions (
    id VARCHAR(64) NOT NULL,
    provider VARCHAR(40) NOT NULL,
    state_hash VARCHAR(64) NOT NULL,
    browser_hash VARCHAR(64) NOT NULL,
    pkce_verifier VARCHAR(255),
    nonce VARCHAR(128),
    expires_at DATETIME(6) NOT NULL,
    consumed_at DATETIME(6),
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_external_auth_expiry ON external_auth_transactions(expires_at, consumed_at);
