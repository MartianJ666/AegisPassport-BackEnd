-- Aegis Passport — per-client application account mapping.
--
-- Records the application account (app_username) a passport owner prefers for a
-- given OAuth client. When the owner (A) authorizes client X they may choose to
-- log in with a different passport account (B); this row remembers that choice
-- so the next authorization for X can reuse B.

CREATE TABLE oauth_client_accounts (
    id             BIGINT       NOT NULL AUTO_INCREMENT,
    client_id      VARCHAR(100) NOT NULL,
    owner_username VARCHAR(100) NOT NULL,
    app_username   VARCHAR(100) NOT NULL,
    created_at     DATETIME(6)  NOT NULL,
    updated_at     DATETIME(6)  NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_client_owner UNIQUE (client_id, owner_username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_client_accounts_client ON oauth_client_accounts (client_id);
CREATE INDEX idx_client_accounts_owner ON oauth_client_accounts (owner_username);
