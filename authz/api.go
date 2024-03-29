package authz

import (
	"net/http"
	"time"

	"penmanship/authnz/authn"
	"penmanship/authnz/utils"

	"github.com/volatiletech/authboss/v3"
)

const CookieName = "penmanship_data"

func Verify(w http.ResponseWriter, r *http.Request) {
	signingKey := utils.GetEnvOrDefault("ENCRYPTION_SIGNING_KEY", "")

	cookie, err := r.Cookie(CookieName)
	if err != nil {
		u := r.Context().Value(authboss.CTXKeyUser)

		if u == nil {
			w.WriteHeader(http.StatusForbidden)

			return
		}

		authnUser := authn.ToUser(u.(authboss.User))

		token, _ := CreateToken(User{
			UUID:          authnUser.UUID,
			EncryptionKey: authnUser.UUID,
		}, signingKey)

		c := http.Cookie{
			Name:     CookieName,
			Value:    token,
			HttpOnly: true,
			Secure:   utils.GetEnvOrDefault("GO_ENV", utils.Development) == utils.Production,
			Expires:  time.Now().UTC().AddDate(0, 1, 0),
		}

		http.SetCookie(w, &c)

		cookie = &c
	}

	token, err := ParseToken(cookie.Value, signingKey)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)

		return
	}

	_, ok := token.Claims.(*claims)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

func Encryption(w http.ResponseWriter, r *http.Request) {
	signingKey := utils.GetEnvOrDefault("ENCRYPTION_SIGNING_KEY", "")

	cookie, err := r.Cookie(CookieName)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)

		return
	}

	token, err := ParseToken(cookie.Value, signingKey)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)

		return
	}

	claims, ok := token.Claims.(*claims)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.Write([]byte(claims.EncryptionKey))
	}
}
