ALTER TABLE users ADD COLUMN violation_count INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN banned_until DATETIME(6) NULL;
CREATE INDEX idx_users_violation_count ON users(violation_count);
CREATE INDEX idx_users_banned_until ON users(banned_until);
