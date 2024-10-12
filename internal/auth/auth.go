package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// CustomClaims represents the custom JWT claims
type CustomClaims struct {
	Sub string `json:"sub"`
	jwt.RegisteredClaims
}

// HashPassword hashes a plain text password using bcrypt.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", errors.New("unable to encrypt password")
	}
	return string(bytes), nil
}

// CheckPasswordHash compares a plain text password with a hashed password.
func CheckPasswordHash(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err
}

// MakeJWT generates a JWT token for a given user ID with a specified expiration time.
func MakeJWT(userId uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {

	if tokenSecret == "" {
		return "", errors.New("token secret not set")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userId.String(),
	})

	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", errors.New("unable to sign string")
	}

	return tokenString, nil
}

// ValidateJWT validates a JWT token and extracts the user ID from the subject claim.
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := &CustomClaims{}
	fmt.Println("ValidateJWT() tokenstring:tokensecret", tokenString, tokenSecret)
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.Nil, fmt.Errorf("unable to parse token: %w", err)
	}

	if !token.Valid {
		return uuid.Nil, errors.New("invalid token")
	}

	subject := claims.Sub
	if subject == "" {
		return uuid.Nil, errors.New("subject nil in claims field")
	}

	id, err := uuid.Parse(subject)
	if err != nil {
		return uuid.Nil, errors.New("error parsing subject")
	}
	return id, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	// header format Bearer TOKEN_STRING
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no Auth header found")
	}

	token, found := strings.CutPrefix(authHeader, "Bearer")
	if !found {
		return "", errors.New("did not find a Bearer token in auth header")
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("no data in token")
	}
	return token, nil
}

// MakeRefreshToken generates a secure random refresh token encoded as a hex string.
// It returns the token and an error if the token generation fails.
func MakeRefreshToken() (string, error) {
	tokenBytes := make([]byte, 32)  // create a byte slice
	_, err := rand.Read(tokenBytes) // fill it with random bytes

	if err != nil {
		return "", errors.New("error creating random token")
	}

	token := hex.EncodeToString(tokenBytes) // encode it to hex string
	return token, nil
}
