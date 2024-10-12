package auth

import (
	"net/http"
	"net/http/httptest"
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
	correctTokenSecret := "test_secret"
	incorrectTokenSecret := "incorrect"
	expires := time.Hour

	token, err := MakeJWT(userId, correctTokenSecret, expires)
	if err != nil {
		t.Fatalf("MakeJWT() returned an error %v", err)
	}

	if token == "" {
		t.Fatalf("MakeJWT() returned an empty string")
	}

	parsedUserId, err := ValidateJWT(token, correctTokenSecret)
	if err != nil {
		t.Fatalf("ValidateJWT() error = %v", err)
	}

	// check validateJWT to see if it errors on incorrect token secret
	_, err = ValidateJWT(token, incorrectTokenSecret)
	if err == nil {
		t.Fatalf("ValidateJWT should have returned error")
	}

	if parsedUserId != userId {
		t.Fatalf("ValidateJWT() error user ids not the same")
	}

}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectedToken string
		expectError   bool
	}{
		{
			name:          "Valid Bearer Token",
			authHeader:    "Bearer valid_token",
			expectedToken: "valid_token",
			expectError:   false,
		},
		{
			name:          "Missing Authorization Header",
			authHeader:    "",
			expectedToken: "",
			expectError:   true,
		},
		{
			name:          "Invalid Authorization Header Format",
			authHeader:    "InvalidHeaderFormat",
			expectedToken: "",
			expectError:   true,
		},
		{
			name:          "Invalid Bearer Token Format",
			authHeader:    "Bearer",
			expectedToken: "",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", tt.authHeader)

			token, err := GetBearerToken(req.Header)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error but got %v", err)
				}
				if token != tt.expectedToken {
					t.Fatalf("expected token %v got %v", tt.expectedToken, err)
				}
			}
		})
	}
}
func TestMakeRefreshToken(t *testing.T) {
	token, err := MakeRefreshToken()
	if err != nil {
		t.Fatalf("MakeRefreshToken() returned an error: %v", err)
	}

	if token == "" {
		t.Fatalf("MakeRefreshToken() returned an empty string")
	}

	if len(token) != 64 {
		t.Fatalf("MakeRefreshToken() returned a token of incorrect length: got %d, want 64", len(token))
	}
}
