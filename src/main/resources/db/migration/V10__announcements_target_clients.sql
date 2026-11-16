-- Announcement audience targeting.
-- NULL / '' means global (every client / all users); otherwise a
-- comma-separated list of OAuth client_id values the announcement is
-- restricted to. Existing rows keep NULL and remain global.
ALTER TABLE announcements ADD COLUMN target_clients VARCHAR(1000) NULL;
