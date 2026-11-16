-- Some installations added this field manually before V11 was registered.
-- Complete the version history without failing on an already matching column.
SET @passport_email_verified_ddl = IF(
 (SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema=DATABASE() AND table_name='users' AND column_name='email_verified')=0,
 'ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE',
 'SELECT 1'
);
PREPARE passport_email_verified_stmt FROM @passport_email_verified_ddl;
EXECUTE passport_email_verified_stmt;
DEALLOCATE PREPARE passport_email_verified_stmt;
