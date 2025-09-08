// Package databasecommon handles DB calls for StatusMaster API.
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
package databasecommon

import (
	credentials "Hrmodule/dbconfig"
	modelscommon "Hrmodule/models/common"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
)

// Request body for StatusMaster
type StatusMasterRequest struct {
	StatusName string `json:"statusname"`
}

// StatusMasterDatabase executes the query
func StatusMasterDatabase(w http.ResponseWriter, r *http.Request) ([]modelscommon.StatusMaster, int, error) {
	connectionString := credentials.Getdatabasemeivan()

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		http.Error(w, fmt.Sprintf("DB open error: %v", err), http.StatusInternalServerError)
		return nil, 0, err
	}
	defer db.Close()

	// Decode request body
	var req StatusMasterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, 0, fmt.Errorf("invalid request body: %v", err)
	}
	defer r.Body.Close()

	if req.StatusName == "" {
		return nil, 0, fmt.Errorf("missing 'statusname' in request body")
	}

	// Execute query
	rows, err := db.Query(modelscommon.MyQueryStatusMaster, req.StatusName)
	if err != nil {
		return nil, 0, fmt.Errorf("error querying DB: %v", err)
	}
	defer rows.Close()

	// Map results
	data, err := modelscommon.RetrieveStatusMaster(rows)
	if err != nil {
		return nil, 0, fmt.Errorf("error retrieving data: %v", err)
	}

	return data, len(data), nil
}
