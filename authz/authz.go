package authz

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type User struct {
	UUID          string
	EncryptionKey string
}

func CreateToken(user User, signingKey string) (string, error) {
	registeredClaims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		NotBefore: jwt.NewNumericDate(time.Now().UTC()),
		Issuer:    issuer,
		Subject:   user.UUID,
		ID:        user.UUID,
	}

	claims := claims{
		user.EncryptionKey,
		registeredClaims,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(signingKey))
}

func ParseToken(token string, signingKey string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(token, &claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
}

type claims struct {
	EncryptionKey string `json:"encryptionKey"`
	jwt.RegisteredClaims
}

const issuer = "penmanship"
