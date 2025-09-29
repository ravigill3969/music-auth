// internal/middleware/response_writer.go
package middleware

import (
	"context"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type responseWriterKey struct{}

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

type userContextKey struct{}

func AuthMiddleware(secret []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return secret, nil
		})

		if err != nil || !token.Valid {
			next.ServeHTTP(w, r)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Helper to fetch claims inside resolvers
func GetUserFromCtx(ctx context.Context) (jwt.MapClaims, bool) {
	claims, ok := ctx.Value(userContextKey{}).(jwt.MapClaims)
	return claims, ok
}
