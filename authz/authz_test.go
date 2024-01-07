package authz

import (
	"testing"
)

func TestCreateToken(t *testing.T) {
	const SigningKey = "1234"
	var user = User{
		UUID:          "1234-1234",
		EncryptionKey: "123456789",
	}

	token, err := CreateToken(user, SigningKey)

	if err != nil {
		t.FailNow()
	}

	parsed, _ := ParseToken(token, SigningKey)

	if expiryTime, _ := parsed.Claims.GetExpirationTime(); expiryTime != nil {
		t.FailNow()
	}
}
