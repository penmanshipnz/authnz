package authz

import (
	"net/http"

	"penmanship/authnz/authn"
	"penmanship/authnz/utils"

	"github.com/volatiletech/authboss/v3"
)

func Encryption(w http.ResponseWriter, r *http.Request) {
	const CookieName = "penmanship_data"

	cookie, err := r.Cookie(CookieName)
	signingKey := utils.GetEnvOrDefault("ENCRYPTION_KEY", "")

	if err != nil {
		u := r.Context().Value(authboss.CTXKeyUser)

		if u == nil {
			w.WriteHeader(http.StatusForbidden)
		}

		authnUser := authn.ToUser(u.(authboss.User))

		token, _ := CreateToken(User{
			UUID:          authnUser.UUID,
			EncryptionKey: authnUser.Password,
		}, signingKey)

		c := http.Cookie{
			Name:  CookieName,
			Value: token,
		}

		http.SetCookie(w, &c)

		cookie = &c
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