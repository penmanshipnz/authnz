ALTER TABLE users
	DROP COLUMN IF EXISTS confirmed,
	DROP COLUMN IF EXISTS confirm_verifier;