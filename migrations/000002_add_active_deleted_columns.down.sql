ALTER TABLE users
	ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true,
	ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT false;