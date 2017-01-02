package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/christoph-k/go-http-jwtfilter"
	jwt "github.com/dgrijalva/jwt-go"
)

func dump(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if ctx == nil {
		return
	}
	tokens := *ctx.Value(jwtfilter.CtxKeyJWT).(*map[string]*jwt.MapClaims)
	if tokens == nil {
		return
	}
	for i, t := range tokens {
		w.Write([]byte(fmt.Sprintf("%v\n%#v\n\n", i, t)))
	}
}

func token(w http.ResponseWriter, r *http.Request) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "testuser",
		"exp":      time.Now().Unix() + 3600,
		"nbf":      time.Now().Unix(),
	})
	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	expiration := time.Now().Add(6 * time.Hour)
	cookie := http.Cookie{Name: "mytoken", Value: tokenString, Path: "/", HttpOnly: true, Expires: expiration}
	cookie2 := http.Cookie{Name: "mytoken2", Value: tokenString, Path: "/", HttpOnly: true, Expires: expiration}
	http.SetCookie(w, &cookie)
	http.SetCookie(w, &cookie2)
	w.Write([]byte("cookie set"))
}

func main() {
	jwtfilter.CookieNames = append(jwtfilter.CookieNames, "mytoken")
	jwtfilter.CookieNames = append(jwtfilter.CookieNames, "mytoken2")

	jwtfilter.Key = []byte("secret")

	http.Handle("/token", http.HandlerFunc(token))
	http.Handle("/", jwtfilter.New(http.HandlerFunc(dump)))

	http.ListenAndServe(":8080", nil)
}
