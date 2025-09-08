// Package databasecommon handles database connections and queries related to SessionData.
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
package databaselogin

import (
	credentials "Hrmodule/dbconfig"
	modelslogin "Hrmodule/models/login"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

// Request struct for SessionData
type SessionDataRequest struct {
	SessionID *string `json:"Session_id"`
}

// SessionDatadatabase executes query and returns SessionData list
func SessionDatadatabase(w http.ResponseWriter, r *http.Request) ([]modelslogin.SessionDataStructure, int, error) {
	// Connection string
	connectionString := credentials.Getdatabasemeivan()

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		http.Error(w, fmt.Sprintf("DB open error: %v", err), http.StatusInternalServerError)
		return nil, 0, err
	}
	defer db.Close()

	// Decode POST body
	var req SessionDataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, 0, fmt.Errorf("invalid request body: %v", err)
	}
	defer r.Body.Close()

	// Fixed: Check for nil pointer and empty string
	if req.SessionID == nil || *req.SessionID == "" {
		return nil, 0, fmt.Errorf("missing or empty 'Session_id' in request body")
	}

	// Execute query
	rows, err := db.Query(modelslogin.MyQuerySessionData, req.SessionID)
	if err != nil {
		return nil, 0, fmt.Errorf("error querying database: %v", err)
	}
	defer rows.Close()

	// Map results
	sessionDataList, err := modelslogin.RetrieveSessionData(rows)
	if err != nil {
		return nil, 0, fmt.Errorf("error retrieving data: %v", err)
	}

	return sessionDataList, len(sessionDataList), nil
}
