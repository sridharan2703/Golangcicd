// Package commoncontrollers exposes API for InboxTasksRole.
//
// --- Creator's Info ---
//
// Creator: Sridharan
//
// Created On:26-08-2025
//
// Last Modified By: Sridharan
//
// Last Modified Date: 26-08-2025
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

// APIResponseforInboxTasksRole standard response
type APIResponseforInboxTasksRole struct {
	Status  int         `json:"Status"`
	Message string      `json:"message"`
	Data    interface{} `json:"Data"`
}

// Token wrapper
type InboxTasksRoleTokenRequest struct {
	Token string `json:"token"`
}

// InboxTasksRole API
func InboxTasksRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	// Extract token
	var req InboxTasksRoleTokenRequest
	if err := json.Unmarshal(body, &req); err == nil && req.Token != "" {
		r.Header.Set("token", req.Token)
	}

	// Authenticate
	if !auth.HandleRequestfor_apiname_ipaddress_token(w, r) {
		return
	}

	// Log + process
	loggedHandler := auth.LogRequestInfo(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := auth.IsValidIDFromRequest(r); err != nil {
			http.Error(w, "Invalid TOKEN provided", http.StatusBadRequest)
			return
		}

		// DB
		data, total, err := database.InboxTasksRoleDatabase(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Build response
		resp := APIResponseforInboxTasksRole{
			Status:  200,
			Message: "Success",
			Data: map[string]interface{}{
				"No Of Records": total,
				"Records":       data,
			},
		}

		// JSON marshal
		jsonResp, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}

		// Encrypt
		enc, err := utils.Encrypt(jsonResp)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		// Send
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"Data": enc,
		})
	}))
	loggedHandler.ServeHTTP(w, r)
}
