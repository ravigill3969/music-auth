package auth

import "database/sql"

type AuthService struct {
	db        *sql.DB
	jwtSecret []byte
}

func New(db *sql.DB, jwt_secret string) *AuthService {
	return &AuthService{db: db, jwtSecret: []byte(jwt_secret)}
}
