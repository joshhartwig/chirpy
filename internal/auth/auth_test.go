package auth

import (
	"testing"
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
