package middleware

import (
	"context"
	"music-auth/internal/common"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type responseWriterKey struct{}

type userContextKey string
const UserContextKey userContextKey = "user"

func ResponseWriterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), responseWriterKey{}, w)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetResponseWriter(ctx context.Context) http.ResponseWriter {
	if rw, ok := ctx.Value(responseWriterKey{}).(http.ResponseWriter); ok {
		return rw
	}
	return nil
}
func AuthMiddleware(secret []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			// No token, just continue (or block if auth required)
			next.ServeHTTP(w, r)
			return
		}

		claims := &common.Claims{}
		token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return secret, nil
		})

		if err != nil || !token.Valid {
			next.ServeHTTP(w, r) // or block with http.Error if strict auth
			return
		}

		// Put claims into context
		ctx := context.WithValue(r.Context(), UserContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetUserFromContext(ctx context.Context) (*common.Claims, bool) {
    claims, ok := ctx.Value(UserContextKey).(*common.Claims)
    return claims, ok
}
