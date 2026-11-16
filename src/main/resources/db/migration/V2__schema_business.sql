-- Aegis Passport — business tables (OAuth, API keys, audit, config).

CREATE TABLE oauth_clients (
    id                     BIGINT       NOT NULL AUTO_INCREMENT,
    client_id              VARCHAR(100) NOT NULL,
    client_secret          VARCHAR(255) NOT NULL,
    client_name            VARCHAR(100) NOT NULL,
    client_description     VARCHAR(500),
    client_icon            VARCHAR(500),
    redirect_uris          VARCHAR(1000) NOT NULL,
    grant_types            VARCHAR(500)  NOT NULL,
    scopes                 VARCHAR(500)  NOT NULL,
    access_token_ttl       INT          NOT NULL,
    refresh_token_ttl      INT          NOT NULL,
    authorization_code_ttl INT          NOT NULL,
    require_pkce           BIT(1)       NOT NULL DEFAULT b'1',
    require_consent        BIT(1)       NOT NULL DEFAULT b'1',
    enabled                BIT(1)       NOT NULL DEFAULT b'1',
    owner_id               BIGINT,
    allowed_roles          VARCHAR(300),
    allowed_users          VARCHAR(1000),
    denied_users           VARCHAR(1000),
    created_at             DATETIME(6)  NOT NULL,
    updated_at             DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_oauth_client_id UNIQUE (client_id),
    CONSTRAINT fk_client_owner FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_client_client_id ON oauth_clients (client_id);

CREATE TABLE oauth_consents (
    id             BIGINT       NOT NULL AUTO_INCREMENT,
    client_id      VARCHAR(100) NOT NULL,
    principal_name VARCHAR(100) NOT NULL,
    scopes         VARCHAR(1000),
    remember       BIT(1)       NOT NULL DEFAULT b'0',
    expires_at     DATETIME(6),
    created_at     DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_client_principal UNIQUE (client_id, principal_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE api_keys (
    id            BIGINT       NOT NULL AUTO_INCREMENT,
    key_name      VARCHAR(100) NOT NULL,
    api_key       VARCHAR(64)  NOT NULL,
    api_secret    VARCHAR(255) NOT NULL,
    scopes        VARCHAR(500),
    enabled       BIT(1)       NOT NULL DEFAULT b'1',
    admin_disabled BIT(1)      NOT NULL DEFAULT b'0',
    expires_at    DATETIME(6),
    last_used_at  DATETIME(6),
    use_count     BIGINT       NOT NULL DEFAULT 0,
    owner_id      BIGINT       NOT NULL,
    created_at    DATETIME(6)  NOT NULL,
    updated_at    DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_apikey_key UNIQUE (api_key),
    CONSTRAINT fk_apikey_owner FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_apikey_key ON api_keys (api_key);

CREATE TABLE audit_logs (
    id             BIGINT       NOT NULL AUTO_INCREMENT,
    event_id       VARCHAR(64)  NOT NULL,
    module         VARCHAR(50)  NOT NULL,
    action         VARCHAR(50)  NOT NULL,
    description    VARCHAR(255),
    operator_name  VARCHAR(100),
    target_id      VARCHAR(100),
    ip_address     VARCHAR(64),
    user_agent     VARCHAR(500),
    request_method VARCHAR(10),
    request_path   VARCHAR(255),
    params         TEXT,
    success        BIT(1)       NOT NULL,
    error_message  VARCHAR(500),
    execution_ms   BIGINT,
    timestamp      DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_audit_event UNIQUE (event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_audit_module ON audit_logs (module);
CREATE INDEX idx_audit_operator ON audit_logs (operator_name);
CREATE INDEX idx_audit_timestamp ON audit_logs (timestamp);
CREATE INDEX idx_audit_success ON audit_logs (success);


CREATE TABLE email_config (
    id            BIGINT       NOT NULL AUTO_INCREMENT,
    smtp_host     VARCHAR(255) NOT NULL,
    smtp_port     INT          NOT NULL,
    smtp_username VARCHAR(255) NOT NULL,
    smtp_password VARCHAR(255) NOT NULL,
    from_email    VARCHAR(255) NOT NULL,
    from_name     VARCHAR(255),
    use_ssl       BIT(1)       NOT NULL DEFAULT b'0',
    use_tls       BIT(1)       NOT NULL DEFAULT b'1',
    enabled       BIT(1)       NOT NULL DEFAULT b'0',
    updated_at    DATETIME(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE system_config (
    id           BIGINT       NOT NULL AUTO_INCREMENT,
    config_key   VARCHAR(100) NOT NULL,
    config_value TEXT,
    description  VARCHAR(255),
    updated_at   DATETIME(6),
    PRIMARY KEY (id),
    CONSTRAINT uk_system_config_key UNIQUE (config_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE signing_keys (
    id          BIGINT      NOT NULL AUTO_INCREMENT,
    key_id      VARCHAR(64) NOT NULL,
    public_key  TEXT        NOT NULL,
    private_key TEXT        NOT NULL,
    active      BIT(1)      NOT NULL DEFAULT b'1',
    created_at  DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_signing_key_id UNIQUE (key_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE TABLE announcements (
    id         BIGINT       NOT NULL AUTO_INCREMENT,
    title      VARCHAR(200) NOT NULL,
    content    TEXT         NOT NULL,
    level      VARCHAR(20)  NOT NULL DEFAULT 'info',
    enabled    BIT(1)       NOT NULL DEFAULT b'1',
    start_time DATETIME(6),
    end_time   DATETIME(6),
    created_by VARCHAR(100) NOT NULL,
    created_at DATETIME(6)  NOT NULL,
    updated_at DATETIME(6)  NOT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
