// Package auth provides authentication and authorization functionality,
// including JWT-based token validation, middleware integration,
// and support for secure API endpoints.
//
// --- Creator's Info ---
//
// Creator: Sridharan
//
// Created On: 25-08-2025
//
// Last Modified By: Sridharan
//
// Last Modified Date: 25-08-2025
package auth

import (
	"fmt"
	"net/http"
	"strings"

	"os"

	"github.com/golang-jwt/jwt/v5"
)

// JwtKey holds the secret key used for signing and verifying JWT tokens.
// It is initialized from the environment variable `JWT_SECRET_KEY`.
var JwtKey []byte

// init initializes the JwtKey by reading the JWT_SECRET_KEY environment variable.
// If the environment variable is not set, the application will panic.
func init() {
	key := os.Getenv("JWT_SECRET_KEY")
	if key == "" {
		panic("JWT_SECRET_KEY environment variable not set")
	}
	JwtKey = []byte(key)
}

// JwtMiddleware checks for JWT token and validates it
func JwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Get token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Ensure token method is HMAC
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return JwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Token is valid -> call next handler
		next.ServeHTTP(w, r)
	})
}
