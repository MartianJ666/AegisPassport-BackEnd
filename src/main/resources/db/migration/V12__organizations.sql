CREATE TABLE organizations (
 id BIGINT NOT NULL AUTO_INCREMENT,
 name VARCHAR(100) NOT NULL,
 description VARCHAR(255),
 created_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 PRIMARY KEY (id),
 CONSTRAINT uk_organizations_name UNIQUE (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE users ADD COLUMN organization_id BIGINT NULL;
CREATE INDEX idx_users_organization ON users (organization_id);
ALTER TABLE users ADD CONSTRAINT fk_users_organization FOREIGN KEY (organization_id) REFERENCES organizations(id);

INSERT INTO organizations(name,created_at,updated_at)
SELECT DISTINCT TRIM(org_name),CURRENT_TIMESTAMP(6),CURRENT_TIMESTAMP(6)
FROM users WHERE org_name IS NOT NULL AND TRIM(org_name) <> '';
UPDATE users u JOIN organizations o ON TRIM(u.org_name)=o.name
SET u.organization_id=o.id,u.org_name=o.name;

ALTER TABLE oauth_clients ADD COLUMN organization_restricted BIT(1) NOT NULL DEFAULT b'0';
ALTER TABLE oauth_clients ADD COLUMN allowed_organizations VARCHAR(1000) NULL;
ALTER TABLE oauth_clients ADD COLUMN denied_organizations VARCHAR(1000) NULL;
