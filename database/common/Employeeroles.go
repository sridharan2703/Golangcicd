// Package databasecommon handles database connections and queries related to DefaultRoleName data.
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
package databasecommon

import (
	credentials "Hrmodule/dbconfig"
	modelscommon "Hrmodule/models/common"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

// request body struct
type DefaultRoleNameRequest struct {
	UserName string `json:"UserName"`
}

func DefaultRoleNamedatabase(w http.ResponseWriter, r *http.Request) ([]modelscommon.DefaultRoleNamestructure, int, error) {
	// Connection string for Postgres
	connectionString := credentials.Getdatabasemeivan()

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		http.Error(w, fmt.Sprintf("DB open error: %v", err), http.StatusInternalServerError)
		return nil, 0, err
	}
	defer db.Close()

	/// Decode POST JSON body
	var req DefaultRoleNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, 0, fmt.Errorf("invalid request body: %v", err)
	}
	defer r.Body.Close()

	if req.UserName == "" {
		return nil, 0, fmt.Errorf("missing 'UserName' in request body")
	}
	// Execute the query
	rows, err := db.Query(modelscommon.MyQueryDefaultRoleName, req.UserName)
	if err != nil {
		return nil, 0, fmt.Errorf("error querying database: %v", err)
	}
	defer rows.Close()

	// Map results
	DefaultRoleNameapi, err := modelscommon.RetrieveDefaultRoleName(rows)
	if err != nil {
		return nil, 0, fmt.Errorf("error retrieving data: %v", err)
	}

	return DefaultRoleNameapi, len(DefaultRoleNameapi), nil
}
