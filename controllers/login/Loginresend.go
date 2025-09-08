// Package controllerslogin provides handlers for OTP-based authentication,
// including secure generation, resending, validation, session management,
// and encrypted API responses.
//
// Specifically, the resend OTP handler ensures:
//   - Secure request validation using token-based authentication
//   - Resending OTP by inserting a new record into the otp_details table
//   - Automatic expiry of OTPs after 45 seconds from insertion
//   - Session tracking through the session_id field
//   - Incremental resend tracking to prevent abuse
//   - Encrypted JSON responses to protect sensitive data
//
// --- Creator's Info ---
//
// Creator: Sridharan
//
// Created On: 26-08-2025
//
// Last Modified By: Sridharan
//
// Last Modified Date: 26-08-2025
package controllerslogin

import (
	"Hrmodule/auth"
	credentials "Hrmodule/dbconfig"
	"Hrmodule/utils"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	_ "github.com/lib/pq"
)

// OTPDetails maps to otp_details table (without id, since it's auto-increment)
type OTPDetailsresend struct {
	Username      string    `json:"username"`
	MobileNo      string    `json:"mobileno"`
	OTP           int       `json:"otp"`
	OTPSendOn     time.Time `json:"otpsendon"`
	OTPVerifiedOn time.Time `json:"otpverifiedon"`
	Status        int       `json:"status"`
	Otpvalidtill  time.Time `json:"otpvalidtill"`
	SessionID     string    `json:"session_id"` // <-- new field
	Resend        int       `json:"Resend"`     // <-- new field
	Token         string    `json:"token"`
}

// InsertOTPHandler inserts a new OTPDetails row
func InsertOTPresendHandler(w http.ResponseWriter, r *http.Request) {
	// Step 1: Parse request body
	var req OTPDetails
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Step 2: If token provided in body, inject into header
	if req.Token != "" {
		r.Header.Set("token", req.Token)
	}

	// Step 3: Authenticate
	if !auth.HandleRequestfor_apiname_ipaddress_token(w, r) {
		return
	}

	loggedHandler := auth.LogRequestInfo(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow only POST
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// DB connection
		connectionString := credentials.Getdatabasemeivan()
		db, err := sql.Open("postgres", connectionString)
		if err != nil {
			http.Error(w, fmt.Sprintf("DB open error: %v", err), http.StatusInternalServerError)
			return
		}
		defer db.Close()

		// Insert query
		query := `
			INSERT INTO otp_details 
			(username, mobileno, otp, otpsendon, status, otpvalidtill, session_id, resend)
			VALUES ($1, $2, $3, NOW(), 0, NOW() + interval '45 seconds', $4, 1)
			RETURNING id;
		`

		var id int
		err = db.QueryRow(query,
			req.Username,
			req.MobileNo,
			req.OTP,
			req.SessionID,
		).Scan(&id)

		if err != nil {
			http.Error(w, "Error inserting: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Success response
		resp := map[string]interface{}{
			"message":    "OTP record inserted successfully",
			"id":         id,
			"session_id": req.SessionID,
		}

		// Encrypt response
		jsonResponse, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}

		encrypted, err := utils.Encrypt(jsonResponse)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"Data": encrypted,
		})
	}))

	loggedHandler.ServeHTTP(w, r)
}
