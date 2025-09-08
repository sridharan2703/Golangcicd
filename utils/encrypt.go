// Package utils provides utility functions including AES-GCM
// encryption for secure response encoding.
//
// --- Creator's Info ---
//
// Creator: Sridharan
//
// Created On:07-07-2025
//
// Last Modified By: Sridharan
//
// Last Modified Date: 09-07-2025
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"math/rand"
	"os"
	"time"

	"github.com/joho/godotenv"
)

var secretKey []byte

// init loads the ENCRYPTION_KEY from the .env file into memory.
// It panics if the key is not found or is not exactly 32 bytes,
// which is required for AES-256 encryption.
func init() {
	err := godotenv.Load()
	if err != nil {
		panic("Error loading .env file")
	}

	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		panic("ENCRYPTION_KEY not set")
	}
	if len(key) != 32 {
		panic("ENCRYPTION_KEY must be 32 bytes")
	}

	secretKey = []byte(key)
}

// Encrypt takes plainText as input and returns an encrypted string
// using AES-GCM encryption. The result is a base64-encoded string
// that includes the nonce used for encryption.
func Encrypt(plainText []byte) (string, error) {
	// Generate random nonce
	rand.Seed(time.Now().UnixNano())
	nonce := make([]byte, 12) // AES-GCM standard nonce size
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}

	// Create AES cipher block
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	// Create GCM mode encryption instance
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Encrypt the data with the nonce
	ciphertext := aesGCM.Seal(nonce, nonce, plainText, nil)

	// Return as base64 string
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
