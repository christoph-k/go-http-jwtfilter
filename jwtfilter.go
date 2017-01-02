package jwtfilter

import (
	"context"
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

type ctxKey string

// CtxKeyJWT ...
const CtxKeyJWT ctxKey = "jwt"

// CookieNames is a list of Cookie-Names to check
var CookieNames []string

// Key is the key to check against
var Key []byte

// New returns the jwfilter-handler
func New(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claimMap := make(map[string]*jwt.MapClaims)
		for _, cookieName := range CookieNames {
			cookie, err := r.Cookie(cookieName)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}

			claims, err := parseToken(cookie.Value, Key)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			claimMap[cookieName] = claims
		}
		ctx := context.WithValue(r.Context(), CtxKeyJWT, &claimMap)
		next.ServeHTTP(w, r.WithContext(ctx))
		return
	})
}

func parseToken(token string, key []byte) (*jwt.MapClaims, error) {
	var claims jwt.MapClaims
	var ok bool
	var parsedtoken *jwt.Token

	parsedtoken, _ = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// @TODO: read method from token
		if _, ok = token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unsupported algorithm: %v", token.Header["alg"])
		}
		return key, nil
	})
	if parsedtoken != nil {
		if claims, ok = parsedtoken.Claims.(jwt.MapClaims); ok && parsedtoken.Valid && claims.Valid() == nil {
			return &claims, nil
		}
	}
	return nil, fmt.Errorf("failed to parse token")
}
