// Package commoncontrollers handles HTTP request routing, authentication, and API response formatting.
//
// --- Creator's Info ---
// Creator: Sridharan
//
// Created On: 25-08-2025
//
// Last Modified By: Sridharan
//
// Last Modified Date: 25-08-2025
package controllerslogin

import (
	"Hrmodule/auth"
	databaselogin "Hrmodule/database/login"
	"Hrmodule/utils"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// APIResponseforSessionData defines standard response structure
type APIResponseforSessionData struct {
	Status  int         `json:"Status"`
	Message string      `json:"message"`
	Data    interface{} `json:"Data"`
}

// Struct for token injection
type SessionDataRequest struct {
	Token string `json:"token"`
}

// SessionData handles POST API for session_data
func SessionData(w http.ResponseWriter, r *http.Request) {
	// Allow only POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	// Extract token
	var req SessionDataRequest
	if err := json.Unmarshal(body, &req); err == nil && req.Token != "" {
		r.Header.Set("token", req.Token)
	}

	// Auth check
	if !auth.HandleRequestfor_apiname_ipaddress_token(w, r) {
		return
	}

	// Log + handler
	loggedHandler := auth.LogRequestInfo(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := auth.IsValidIDFromRequest(r); err != nil {
			http.Error(w, "Invalid TOKEN provided", http.StatusBadRequest)
			return
		}

		// DB query
		sessionDataList, totalCount, err := databaselogin.SessionDatadatabase(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Response
		response := APIResponseforSessionData{
			Status:  200,
			Message: "Success",
			Data: map[string]interface{}{
				"No Of Records": totalCount,
				"Records":       sessionDataList,
			},
		}

		// Marshal
		jsonResponse, err := json.MarshalIndent(response, "", "    ")
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

		// Send
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"Data": encrypted,
		})
	}))
	loggedHandler.ServeHTTP(w, r)
}
