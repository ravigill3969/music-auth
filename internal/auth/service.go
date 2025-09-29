package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"music-auth/graph/model"
	"music-auth/internal/middleware"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	db        *sql.DB
	jwtSecret []byte
}

func New(db *sql.DB, jwt_secret string) *AuthService {
	return &AuthService{db: db, jwtSecret: []byte(jwt_secret)}
}

func (a *AuthService) Register(username, email, password string) (string, *User, error) {

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

func (a *AuthService) GetUserInfo(ctx context.Context) (*model.GetUserInfoResponse, error) {
	claims, ok := middleware.GetUserFromContext(ctx)
	fmt.Println(claims)
	if !ok {
		return &model.GetUserInfoResponse{
			Success: false,
			Message: "unauthorized",
			User:    nil,
		}, nil
	}

	userID := claims.UserID

	query := `
    SELECT id, username, email, subscription_type, ending_subscription_date
    FROM users
    WHERE id = $1
`

	var user model.GetUser
	err := a.db.QueryRow(query, userID).Scan(
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

func (a *AuthService) UpdatePassword(ctx context.Context, oldPassword, newPassword string) (*model.BasicResponse, error) {
	claims, ok := middleware.GetUserFromContext(ctx)

	if !ok {
		return nil, fmt.Errorf("Unauthorized")
	}

	userID := claims.UserID

	query := `SELECT password FROM users WHERE id = $1`

	res := a.db.QueryRow(query, userID)

	var password string
	err := res.Scan(&password)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("unable to update password, try again later")
		}

		return nil, fmt.Errorf("internal server error")
	}

	ok = CheckPasswordHash(oldPassword, password)

	if !ok {
		return nil, fmt.Errorf("passwords donot match")
	}

	hashedPassword, err := HashPassword(newPassword)

	if err != nil {
		return nil, fmt.Errorf("unable to update password, try again later")
	}

	query = `UPDATE users SET password = $1 WHERE id = $2`

	_, err = a.db.Exec(query, userID, hashedPassword)

	if err != nil {
		return nil, fmt.Errorf("unable to update password, try again later")
	}

	return &model.BasicResponse{
		Success: true,
		Message: "Password updated",
	}, nil
}

func (a *AuthService) UpdateEmail(ctx context.Context, newEmail string) error {
	claims, ok := middleware.GetUserFromContext(ctx)

	if !ok {
		return fmt.Errorf("Unauthorized")
	}

	userID := claims.UserID

	query := `UPDATE users SET email = $1 WHERE id = $2`

	_, err := a.db.Exec(query, newEmail, userID)

	if err != nil {
		return fmt.Errorf("email update unsuccessfull, try again later")
	}

	return nil

}

func (a *AuthService) UpdateUsername(ctx context.Context, newUsername string) error {

	claims, ok := middleware.GetUserFromContext(ctx)

	if !ok {
		return fmt.Errorf("Unauthorized")
	}

	userID := claims.UserID

	query := `UPDATE users SET username = $1 WHERE id = $2`

	result, err := a.db.Exec(query, newUsername, userID)
	if err != nil {
		return fmt.Errorf("username update unsuccessful, try again later")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("username update unsuccessful, try again later")
	}

	if rowsAffected == 0 {
		return fmt.Errorf("username update unsuccessful, try again later")
	}

	return nil
}
