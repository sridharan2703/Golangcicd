// Package controllersnoc contains APIs for NOC (No Objection Certificate) master record management.
//
// This API updates NOC master records with badge, priority, and starred status based on cover page number.
//
// Path: NOC Management
//
// --- Creator's Info ---
// Creator: Sridharan
//
// Created On: 26-08-2025
//
// Last Modified By: Sridharan
//
// Last Modified Date: 26-08-2025
package controllerscommon

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
	"strings"

	_ "github.com/lib/pq"
)

// NOCUpdateRequest represents the expected JSON structure for updating NOC master records.
type NOCUpdateRequest struct {
	CoverPageNo string `json:"coverpageno"` // identifier for the record to be updated
	Badge       *int   `json:"badge"`       // Badge value (int, required)
	Priority    *int   `json:"priority"`    // Priority value (nullable)
	Starred     *int   `json:"starred"`     // Starred status: 0 = false, 1 = true (nullable)
	Token       string `json:"token"`       // Token can also come from request body
}

// APIResponse defines the JSON response structure used by API endpoints.
type APIResponse struct {
	Status       int    `json:"status"`        // HTTP-like status code
	Message      string `json:"message"`       // Human-readable message
	RowsAffected int64  `json:"rows_affected"` // Number of rows affected by the update
}

// UpdateNOCMaster updates the noc_master table with badge, priority, and starred values.
func UpdateNOCMaster(coverPageNo string, badge, priority, starred *int) (int64, error) {
	connectionString := credentials.Getdatabasemeivan()

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return 0, fmt.Errorf("DB open error: %v", err)
	}
	defer db.Close()

	var setParts []string
	var args []interface{}
	argIndex := 1

	if badge != nil {
		setParts = append(setParts, fmt.Sprintf("badge = $%d", argIndex))
		args = append(args, *badge)
		argIndex++
	}

	if priority != nil {
		setParts = append(setParts, fmt.Sprintf("priority = $%d", argIndex))
		args = append(args, *priority)
		argIndex++
	}

	if starred != nil {
		setParts = append(setParts, fmt.Sprintf("starred = $%d", argIndex))
		args = append(args, *starred) // keep as int (0 or 1)
		argIndex++
	}

	if len(setParts) == 0 {
		return 0, fmt.Errorf("at least one field must be provided for update")
	}

	query := fmt.Sprintf(
		"UPDATE noc_master SET %s WHERE coverpageno = $%d",
		strings.Join(setParts, ", "), argIndex,
	)
	args = append(args, coverPageNo)

	result, err := db.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("update error: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected error: %v", err)
	}

	return rowsAffected, nil
}

// NOCUpdateHandler handles POST requests to the /NOCUpdate endpoint.
func NOCUpdateHandler(w http.ResponseWriter, r *http.Request) {
	// Read body (so we can inject token if provided in JSON)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body)) // restore for downstream

	var req NOCUpdateRequest
	_ = json.Unmarshal(body, &req)

	// If token provided in body, inject into header
	if req.Token != "" {
		r.Header.Set("token", req.Token)
	}

	// Authenticate (token/IP validation)
	if !auth.HandleRequestfor_apiname_ipaddress_token(w, r) {
		return
	}

	// Wrap logic with logging
	loggedHandler := auth.LogRequestInfo(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate common token
		if err := auth.IsValidIDFromRequest(r); err != nil {
			http.Error(w, "Invalid TOKEN provided", http.StatusBadRequest)
			return
		}

		// Allow only POST
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse JSON body again and validate required fields
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		if req.CoverPageNo == "" {
			http.Error(w, "Missing required field: coverpageno", http.StatusBadRequest)
			return
		}

		// // FIX: req.Badge is *int; check for nil (not empty string)
		// if req.Badge == nil {
		// 	http.Error(w, "Missing required field: badge", http.StatusBadRequest)
		// 	return
		// }

		// Update NOC master record
		rowsAffected, err := UpdateNOCMaster(req.CoverPageNo, req.Badge, req.Priority, req.Starred)

		// Build API response
		var response APIResponse
		if err != nil {
			response = APIResponse{
				Status:       500,
				Message:      "Failed to update NOC master: " + err.Error(),
				RowsAffected: 0,
			}
		} else if rowsAffected == 0 {
			response = APIResponse{
				Status:       404,
				Message:      fmt.Sprintf("No record found with coverpageno: %s", req.CoverPageNo),
				RowsAffected: rowsAffected,
			}
		} else {
			response = APIResponse{
				Status:       200,
				Message:      fmt.Sprintf("NOC master updated successfully for coverpageno: %s", req.CoverPageNo),
				RowsAffected: rowsAffected,
			}
		}

		// Marshal + Encrypt response
		responseBytes, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "Failed to serialize JSON", http.StatusInternalServerError)
			return
		}

		encrypted, err := utils.Encrypt(responseBytes)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		// Send encrypted response
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"Data": encrypted,
		})
	}))

	// Execute logged handler
	loggedHandler.ServeHTTP(w, r)
}
