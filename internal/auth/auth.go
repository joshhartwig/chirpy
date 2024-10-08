package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

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
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.Nil, errors.New("unable to validateJWT")
	}

	var id uuid.UUID
	for k, v := range claims {
		if k == "sub" {
			subject, ok := v.(string)
			if !ok {
				return uuid.Nil, errors.New("invalid subject claim")
			}
			parsedId, err := uuid.Parse(subject)
			if err != nil {
				return uuid.Nil, errors.New("invalid UUID format in subject claim")
			}
			id = parsedId
		}
	}

	if !token.Valid {
		return uuid.Nil, errors.New("invalid token")
	}

	return id, nil
}
