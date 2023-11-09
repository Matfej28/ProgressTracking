package jwtToken

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"google.golang.org/grpc/metadata"
)

type Claims struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	jwt.StandardClaims
}

func CreateToken(jwtKey string, username string, email string) (string, error) {
	expirationTime := time.Now().Add(30 * time.Minute)
	claims := &Claims{
		Username: username,
		Email:    email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) //declaring the token

	signedToken, err := token.SignedString([]byte(jwtKey)) //signing the token
	if err != nil {
		return "", err
	}

	return signedToken, err
}

func CheckToken(jwtKey string, ctx context.Context) error {
	headers, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return fmt.Errorf("no metadata found in context")
	}

	headerTokens := headers.Get("token")
	if len(headerTokens) < 1 {
		return fmt.Errorf("no token found in metadata")
	}

	token, err := jwt.ParseWithClaims(headerTokens[0], &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})
	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}

func UsernameFromToken(jwtKey string, ctx context.Context) (username string, err error) {
	headers, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("no metadata found in context")
	}

	headerTokens := headers.Get("token")
	if len(headerTokens) < 1 {
		return "", fmt.Errorf("no token found in metadata")
	}

	token, err := jwt.ParseWithClaims(headerTokens[0], &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtKey), nil
	})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*Claims); ok {
		return claims.Username, nil
	}

	return "", nil
}
