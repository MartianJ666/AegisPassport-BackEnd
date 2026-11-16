ALTER TABLE external_auth_transactions ADD COLUMN intent VARCHAR(32) NOT NULL DEFAULT 'LOGIN';
