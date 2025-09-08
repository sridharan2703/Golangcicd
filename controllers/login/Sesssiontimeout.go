// Package common contains APIs that are commonly used across the application and are grouped together for reusability.
//
// This API marks a user session as inactive upon logout or timeout.
//
// Path: Login Page
//
// --- Creator's Info ---
// Creator: Sridharan
//
// Created On: 09-07-2025
//
// Last Modified By: Sridharan
//
// Last Modified Date: 09-07-2025
package controllerslogin

import (
	"Hrmodule/auth"
	credentials "Hrmodule/dbconfig"
	"Hrmodule/utils"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	_ "github.com/lib/pq"
)

// SessionRequest represents the expected JSON structure for a session timeout request.
type SessionRequest struct {
	SessionID   string `json:"session_id"`  // SessionID is the identifier of the session to be updated.
	Token       string `json:"token"`       // Token can also come from request body
	IdleTimeout int    `json:"idletimeout"` // IdleTimeout value to be set (0 or 1)
}

// APIResponse defines the JSON response structure used by API endpoints.
type APIResponse struct {
	Status  int    `json:"status"`  // HTTP-like status code
	Message string `json:"message"` // Human-readable message
}

// UpdateSessionLogout updates the Is_Active flag to 0, sets idletimeout, and sets the Logout_Date to NOW()
func UpdateSessionLogout(sessionId string, idleTimeout int) error {
	// Connection string for Postgres
	connectionString := credentials.Getdatabasemeivan()

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return fmt.Errorf("DB open error: %v", err)
	}
	defer db.Close()

	// ✅ Fixed Postgres syntax: proper placeholders and comma placement
	query := `
		UPDATE session_data 
		SET Is_Active = 0, idletimeout = $2, Logout_Date = NOW() 
		WHERE Session_Id = $1`

	_, err = db.Exec(query, sessionId, idleTimeout)
	if err != nil {
		return fmt.Errorf("update error: %v", err)
	}

	return nil
}

// SessionTimeoutHandler handles POST requests to the /SessionTimeout endpoint.
func SessionTimeoutHandler(w http.ResponseWriter, r *http.Request) {
	// Step 0: Read and parse body (so we can inject token if provided in JSON)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body)) // restore for downstream

	var req SessionRequest
	_ = json.Unmarshal(body, &req)

	// If token provided in body, inject into header
	if req.Token != "" {
		r.Header.Set("token", req.Token)
	}

	// Step 1: Authenticate (token/IP validation)
	if !auth.HandleRequestfor_apiname_ipaddress_token(w, r) {
		return
	}

	// Wrap logic with logging
	loggedHandler := auth.LogRequestInfo(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Step 2: Validate common token
		if err := auth.IsValidIDFromRequest(r); err != nil {
			http.Error(w, "Invalid TOKEN provided", http.StatusBadRequest)
			return
		}

		// Step 3: Allow only POST
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Step 4: Parse JSON body again and validate required fields
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		// Validate required session_id
		if req.SessionID == "" {
			http.Error(w, "Missing required field: session_id", http.StatusBadRequest)
			return
		}

		// Validate idletimeout value (should be 0 or 1, default to 0 if not provided)
		if req.IdleTimeout != 0 && req.IdleTimeout != 1 {
			req.IdleTimeout = 0 // Default to 0 if invalid value provided
		}

		// Step 5: Update session logout with idletimeout parameter
		err := UpdateSessionLogout(req.SessionID, req.IdleTimeout)

		// Step 6: Build API response
		var response APIResponse
		if err != nil {
			response = APIResponse{Status: 500, Message: "Failed to update session: " + err.Error()}
		} else {
			response = APIResponse{Status: 200, Message: fmt.Sprintf("Session updated successfully with idletimeout=%d", req.IdleTimeout)}
		}

		// Step 7: Marshal response
		responseBytes, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "Failed to serialize JSON", http.StatusInternalServerError)
			return
		}

		// Step 8: Encrypt response
		encrypted, err := utils.Encrypt(responseBytes)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		// Step 9: Send encrypted response
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"Data": encrypted,
		})
	}))

	// Step 10: Execute logged handler
	loggedHandler.ServeHTTP(w, r)
}
