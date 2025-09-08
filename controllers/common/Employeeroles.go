// Package commoncontrollers handles HTTP request routing, authentication,
// and API response formatting for the application.
//
// --- Creator's Info ---
//
// Creator: Sridharan
//
// Created On:30-07-2025
//
// Last Modified By: Sridharan
//
// Last Modified Date: 30-07-2025
package controllerscommon

import (
	"Hrmodule/auth"
	database "Hrmodule/database/common"
	"Hrmodule/utils"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// APIResponseforDefaultRoleName defines the standard structure of the API response.
type APIResponseforDefaultRoleName struct {
	Status  int         `json:"Status"`
	Message string      `json:"message"`
	Data    interface{} `json:"Data"`
}

// Struct for request body (for token injection + flexibility for other fields later)
type DefaultRoleNameRequest struct {
	Token string `json:"token"`
	// Add more request params here if needed in future
}

// DefaultRoleName handles the HTTP POST request to fetch DefaultRoleName data for Employees.
func DefaultRoleName(w http.ResponseWriter, r *http.Request) {
	// Allow only POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}

	// Step 1: Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body)) // restore for downstream

	var req DefaultRoleNameRequest
	if err := json.Unmarshal(body, &req); err == nil && req.Token != "" {
		// Step 2: Inject token into header for compatibility with existing validation
		r.Header.Set("token", req.Token)
	}

	// Step 3: Authenticate
	if !auth.HandleRequestfor_apiname_ipaddress_token(w, r) {
		return
	}

	// Step 4: Logging middleware
	loggedHandler := auth.LogRequestInfo(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Step 5: Validate token
		if err := auth.IsValidIDFromRequest(r); err != nil {
			http.Error(w, "Invalid TOKEN provided", http.StatusBadRequest)
			return
		}

		// Step 6: DB query
		DefaultRoleNameData, totalCount, err := database.DefaultRoleNamedatabase(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Step 7: Response struct
		response := APIResponseforDefaultRoleName{
			Status:  200,
			Message: "Success",
			Data: map[string]interface{}{
				"No Of Records": totalCount,
				"Records":       DefaultRoleNameData,
			},
		}

		// Step 8: Marshal to JSON
		jsonResponse, err := json.MarshalIndent(response, "", "    ")
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}

		// Step 9: Encrypt
		encrypted, err := utils.Encrypt(jsonResponse)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		// Step 10: Send response
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"Data": encrypted,
		})
	}))

	// Step 11: Execute with logging
	loggedHandler.ServeHTTP(w, r)
}
