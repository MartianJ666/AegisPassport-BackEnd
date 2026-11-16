-- External account onboarding (third-party new users) and link-intent transactions.
ALTER TABLE users ADD COLUMN needs_setup BIT(1) NOT NULL DEFAULT b'0';
ALTER TABLE external_auth_transactions ADD COLUMN user_id BIGINT NULL;
ALTER TABLE external_auth_transactions ADD CONSTRAINT fk_external_tx_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
