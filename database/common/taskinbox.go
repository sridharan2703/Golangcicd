// Package databasecommon handles DB calls for InboxTasksRole API.
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

// Request body for InboxTasksRole
type InboxTasksRoleRequest struct {
	EmpID        string `json:"empid"`
	AssignedRole string `json:"assignedrole"`
}

// InboxTasksRoleDatabase executes getinboxtasks_role
func InboxTasksRoleDatabase(w http.ResponseWriter, r *http.Request) ([]modelscommon.InboxTasksRole, int, error) {
	connectionString := credentials.Getdatabasemeivan()

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		http.Error(w, fmt.Sprintf("DB open error: %v", err), http.StatusInternalServerError)
		return nil, 0, err
	}
	defer db.Close()

	// Decode request
	var req InboxTasksRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, 0, fmt.Errorf("invalid request body: %v", err)
	}
	defer r.Body.Close()

	// Run query
	rows, err := db.Query(modelscommon.MyQueryInboxTasksRole, req.EmpID, req.AssignedRole)
	if err != nil {
		return nil, 0, fmt.Errorf("error querying DB: %v", err)
	}
	defer rows.Close()

	// Map results
	data, err := modelscommon.RetrieveInboxTasksRole(rows)
	if err != nil {
		return nil, 0, fmt.Errorf("error retrieving data: %v", err)
	}

	return data, len(data), nil
}
