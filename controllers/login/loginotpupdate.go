// Package controllerslogin provides handlers for managing OTP-based
// authentication, including secure validation of OTP records against
// the database, session tracking, request validation, and encrypted API responses.
//
// It ensures:
//   - Secure request validation using token-based authentication
//   - Validation of OTP details (username, mobile number, session ID, etc.)
//   - Automatic expiry check for OTPs using validity window
//   - Updates OTP status and verification timestamp on successful validation
//   - Encrypted response payloads for added security
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

	_ "github.com/lib/pq"
)

// ValidateOTPRequest represents the request body for OTP validation
type ValidateOTPRequest struct {
	Token     string `json:"token"`
	Username  string `json:"username"`
	MobileNo  int64  `json:"mobileno"`
	SessionID string `json:"session_id"`
	OTP       int    `json:"otp"`
}

// ValidateOTPHandler validates OTP using ValidCheck logic
func ValidateOTPHandler(w http.ResponseWriter, r *http.Request) {
	// Step 1: Parse request body
	var req ValidateOTPRequest
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
		// Step 4: Allow only POST
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Step 5: Validate required fields
		if req.Username == "" || req.MobileNo == 0 || req.SessionID == "" || req.OTP == 0 {
			http.Error(w, "username, mobileno, session_id and otp are required", http.StatusBadRequest)
			return
		}

		// Step 6: DB Connection
		connectionString := credentials.Getdatabasemeivan()
		db, err := sql.Open("postgres", connectionString)
		if err != nil {
			http.Error(w, fmt.Sprintf("DB open error: %v", err), http.StatusInternalServerError)
			return
		}
		defer db.Close()

		// Step 7: Check ValidCheck logic with OTP validation
		checkQuery := `
			SELECT 
				id,
				CASE WHEN (otpverifiedon IS NULL AND status = 0 AND otpvalidtill >= NOW()) 
					THEN '1' 
					ELSE '0' 
				END as validcheck
			FROM otp_details 
			WHERE username = $1 
			  AND mobileno = $2 
			  AND session_id = $3 
			  AND otp = $4
			  AND status = 0
			  AND otpverifiedon IS NULL 
			ORDER BY otpsendon DESC 
			LIMIT 1;
		`

		var id int
		var validCheck string

		err = db.QueryRow(checkQuery, req.Username, req.MobileNo, req.SessionID, req.OTP).Scan(&id, &validCheck)

		if err != nil {
			if err == sql.ErrNoRows {
				// No matching record found
				resp := map[string]interface{}{
					"success":    false,
					"message":    "Invalid OTP or OTP not found",
					"validcheck": "0",
				}
				sendEncryptedResponse(w, resp)
				return
			}
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Step 8: Check if validcheck = 1 (needs update)
		if validCheck == "1" {
			// Update otpverifiedon and status
			updateQuery := `
				UPDATE otp_details 
				SET otpverifiedon = NOW(), status = 1
				WHERE id = $1
			`

			_, err = db.Exec(updateQuery, id)
			if err != nil {
				http.Error(w, "Error updating OTP verification: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// Success response
			resp := map[string]interface{}{
				"success":    true,
				"message":    "OTP verified successfully",
				"validcheck": "1",
				"username":   req.Username,
				"mobileno":   req.MobileNo,
				"session_id": req.SessionID,
			}
			sendEncryptedResponse(w, resp)
		} else {
			// validcheck = 0, no update needed
			resp := map[string]interface{}{
				"success":    false,
				"message":    "OTP expired or invalid",
				"validcheck": "0",
			}
			sendEncryptedResponse(w, resp)
		}
	}))

	// Run the logged handler
	loggedHandler.ServeHTTP(w, r)
}

// Helper function to send encrypted response
func sendEncryptedResponse(w http.ResponseWriter, resp map[string]interface{}) {
	// Marshal to JSON
	jsonResponse, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	// Encrypt
	encrypted, err := utils.Encrypt(jsonResponse)
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	// Send encrypted response
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"Data": encrypted,
	})
}
