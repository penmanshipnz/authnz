package authz

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type User struct {
	UUID          string
	EncryptionKey string
}

func CreateAccessToken(user User, signingKey string, noExpiry bool) (string, error) {
	registeredClaims := claims{"",
		jwt.RegisteredClaims{
			Issuer: issuer,
		},
	}

	if !noExpiry {
		registeredClaims.ExpiresAt = jwt.NewNumericDate(oneHourFromNow())
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, registeredClaims)

	return token.SignedString([]byte(signingKey))
}

func CreateRefreshToken(user User, signingKey string, noExpiry bool) (string, error) {
	registeredClaims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    issuer,
		Subject:   user.UUID,
		ID:        user.UUID,
	}

	if !noExpiry {
		registeredClaims.ExpiresAt = jwt.NewNumericDate(oneMonthFromNow())
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

func oneHourFromNow() time.Time {
	return time.Now().Local().Add(2 * time.Hour).Truncate(time.Second)
}

func oneMonthFromNow() time.Time {
	return time.Now().Local().AddDate(0, 1, 0).Truncate(time.Second)
}
