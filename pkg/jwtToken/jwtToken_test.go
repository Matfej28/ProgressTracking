package jwtToken

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestCreateToken(t *testing.T) {
	jwtKey := "jwtKey123"
	username := "user"
	email := "user@gmail.com"
	token, err := CreateToken(jwtKey, username, email)
	if err != nil {
		t.Errorf("Token creating FAILED: %v", err)
		return
	} else if len(token) == 0 {
		t.Errorf("Token creating FAILED: token is not long enough!")
	} else {
		t.Logf("Token creating PASSED!")
	}
}

func TestCheckToken(t *testing.T) {
	jwtKey := "jwtKey123"
	username := "user"
	email := "user@gmail.com"
	token, err := CreateToken(jwtKey, username, email)
	if err != nil {
		t.Errorf("Token checking FAILED: Token creating FAILED: %v", err)
		return
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), "token", token)
	err = CheckToken(jwtKey, ctx)
	if err != nil {
		t.Errorf("Token checking FAILED: %v", err)
	} else {
		t.Logf("Token checking PASSED!")
	}
}

func TestUsernameFromToken(t *testing.T) {
	jwtKey := "jwtKey123"
	username := "user"
	email := "user@gmail.com"
	token, err := CreateToken(jwtKey, username, email)
	if err != nil {
		t.Errorf("Token checking FAILED: Token creating FAILED: %v", err)
		return
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), "token", token)
	retrievedUsername, err := UsernameFromToken(jwtKey, ctx)
	if username != retrievedUsername {
		t.Errorf("Username retrieving from token FAILED: %v", err)
	} else {
		t.Logf("Username retrieving from token PASSED!")
	}
}
