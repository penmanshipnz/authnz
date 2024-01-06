package authz

import (
	"testing"
)

func TestCreateExpiringAccessToken(t *testing.T) {
	const SigningKey = "1234"
	var user = User{
		UUID:          "1234-1234",
		EncryptionKey: "123456789",
	}

	token, err := CreateAccessToken(user, SigningKey, false)

	if err != nil {
		t.FailNow()
	}

	parsed, _ := ParseToken(token, SigningKey)

	if parsedIssuer, _ := parsed.Claims.GetIssuer(); parsedIssuer != issuer {
		t.FailNow()
	}

	if expiryTime, _ := parsed.Claims.GetExpirationTime(); !expiryTime.Equal(oneHourFromNow()) {
		t.FailNow()
	}
}

func TestCreateIndefiniteAccessToken(t *testing.T) {
	const SigningKey = "1234"
	var user = User{
		UUID:          "1234-1234",
		EncryptionKey: "123456789",
	}

	token, err := CreateAccessToken(user, SigningKey, true)

	if err != nil {
		t.FailNow()
	}

	parsed, _ := ParseToken(token, SigningKey)

	if expiryTime, _ := parsed.Claims.GetExpirationTime(); expiryTime != nil {
		t.FailNow()
	}
}

func TestCreateExpiringRefreshToken(t *testing.T) {
	const SigningKey = "1234"
	var user = User{
		UUID:          "1234-1234",
		EncryptionKey: "123456789",
	}

	token, err := CreateRefreshToken(user, SigningKey, false)

	if err != nil {
		t.FailNow()
	}

	parsed, _ := ParseToken(token, SigningKey)

	if parsedIssuer, _ := parsed.Claims.GetIssuer(); parsedIssuer != issuer {
		t.FailNow()
	}

	if expiryTime, _ := parsed.Claims.GetExpirationTime(); !expiryTime.Equal(oneMonthFromNow()) {
		t.FailNow()
	}
}

func TestCreateIndefiniteRefreshToken(t *testing.T) {
	const SigningKey = "1234"
	var user = User{
		UUID:          "1234-1234",
		EncryptionKey: "123456789",
	}

	token, err := CreateRefreshToken(user, SigningKey, true)

	if err != nil {
		t.FailNow()
	}

	parsed, _ := ParseToken(token, SigningKey)

	if expiryTime, _ := parsed.Claims.GetExpirationTime(); expiryTime != nil {
		t.FailNow()
	}
}
