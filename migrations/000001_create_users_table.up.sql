CREATE TABLE IF NOT EXISTS users(
	uuid UUID NOT NULL UNIQUE,
	email VARCHAR(320) NOT NULL UNIQUE,
	password VARCHAR(80) NOT NULL UNIQUE,
	PRIMARY KEY(uuid, email)
);
