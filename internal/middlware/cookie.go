// internal/middleware/response_writer.go
package middleware

import (
	"context"
	"net/http"
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
