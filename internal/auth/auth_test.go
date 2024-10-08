package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	password := "mysecret"

	hashed, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hashed == "" {
		t.Fatalf("HashPassword() return an empty string")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "mysecret"
	hashedPassword, err := HashPassword(password)

	if err != nil {
		t.Fatalf("error hashing password %v", err)
	}

	err = CheckPasswordHash(password, hashedPassword)
	if err != nil {
		t.Fatalf("error password and hash are not the same %v", err)
	}

	wrongPassword := "wrong"
	err = CheckPasswordHash(wrongPassword, hashedPassword)
	if err == nil {
		t.Fatalf("expecting an error got nothing %v", err)
	}

}

func TestMakeJWT(t *testing.T) {
	userId := uuid.New()
	tokenSecret := "test_secret"
	expires := time.Hour

	token, err := MakeJWT(userId, tokenSecret, expires)
	if err != nil {
		t.Fatalf("MakeJWT() returned an error %v", err)
	}

	if token == "" {
		t.Fatalf("MakeJWT() returned an empty string")
	}
}

func TestValidateJWT(t *testing.T) {
	userId := uuid.New()
	tokenSecret := "test_secret"
	expires := time.Hour

	token, err := MakeJWT(userId, tokenSecret, expires)
	if err != nil {
		t.Fatalf("MakeJWT() returned an error %v", err)
	}

	if token == "" {
		t.Fatalf("MakeJWT() returned an empty string")
	}

	parsedUserId, err := ValidateJWT(token, tokenSecret)
	if err != nil {
		t.Fatalf("ValidateJWT() error = %v", err)
	}

	if parsedUserId != userId {
		t.Fatalf("ValidateJWT() error user ids not the same")
	}
}
