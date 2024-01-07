package utils

import (
	"encoding/base64"
	"os"

	"github.com/gorilla/securecookie"
)

const (
	Development string = "development"
	Production  string = "production"
)

func GenerateRandomKey() string {
	return base64.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(64))
}

func GetEnvOrDefault(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)

	if !exists {
		value = defaultValue
	}

	return value
}
