package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"music-auth/graph/model"
	middleware "music-auth/internal/middlware"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	db        *sql.DB
	jwtSecret []byte
}

const HTTPRequest = "httpRequest"
const HTTPResponseWriter = "httpResponseWriter"

func New(db *sql.DB, jwt_secret string) *AuthService {
	return &AuthService{db: db, jwtSecret: []byte(jwt_secret)}
}

func (a *AuthService) RegisterUser(username, email, password string) (string, *User, error) {

	if username == "" || email == "" || password == "" {
		return "", nil, fmt.Errorf("username, email and password, All fields are required")
	}

	hashedPassword, err := HashPassword(password)

	if err != nil {
		return "", nil, fmt.Errorf("unable to hash password %w", err)
	}

	query := `INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email`

	var user User

	err = a.db.QueryRow(query, username, email, hashedPassword).Scan(&user.ID, &user.Username, &user.Email)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Constraint {
			case "users_email_key":
				fmt.Println("email")
				return "", nil, errors.New("email already registered")
			case "users_username_key":
				fmt.Println("username")
				return "", nil, errors.New("username already taken")
			}
		}
		return "", nil, fmt.Errorf("could not insert user: %w", err)
	}

	token, err := a.GenerateToken(&user)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return token, &user, nil
}

func (a *AuthService) Login(email, password string) (string, error) {
	if email == "" || password == "" {
		return "", errors.New("email and password are required")
	}

	var user User

	query := `SELECT id, username, email, password FROM users WHERE email = $1`
	err := a.db.QueryRow(query, email).Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.New("user not found")
		}
		return "", err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return "", errors.New("invalid password")
	}

	token, err := a.GenerateToken(&user)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (r *AuthService) GetUserInfo(ctx context.Context) (*model.GetUserInfoResponse, error) {
	claims, ok := middleware.GetUserFromCtx(ctx)
	if !ok {
		return &model.GetUserInfoResponse{
			Success: false,
			Message: "unauthorized",
			User:    nil,
		}, nil
	}

	userID := claims["user_id"].(string)

	query := `
    SELECT id, username, email, subscription_type, ending_subscription_date
    FROM users
    WHERE id = $1
`

	var user model.GetUser
	err := r.db.QueryRow(query, userID).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.AccountType,
		&user.EndingDate,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("db error: %w", err)
	}

	return &model.GetUserInfoResponse{
		Success: true,
		User: &model.GetUser{
			ID:          user.ID,
			Username:    user.Username,
			Email:       user.Email,
			AccountType: user.AccountType,
			EndingDate:  user.EndingDate,
		},
	}, nil
}
