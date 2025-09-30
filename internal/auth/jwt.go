package auth

import (
	"errors"
	"music-auth/internal/common"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (a *AuthService) GenerateToken(user *User) (string, error) {
	claims := &common.Claims{
		UserID: user.ID,
		Email:  user.Email,
		Tenant : "music-store",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.jwtSecret)
}

func (a *AuthService) ParseToken(tokenStr string) (*common.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &common.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return a.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*common.Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

