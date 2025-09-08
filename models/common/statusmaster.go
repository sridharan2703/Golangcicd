// Package modelscommon contains data structures and DB scan logic for StatusMaster API.
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
package modelscommon

import (
	"database/sql"
	"fmt"
)

const MyQueryStatusMaster = `
SELECT statusid, statusdescription
FROM statusmaster
WHERE statusname = $1
`

// StatusMaster defines structure for statusmaster table
type StatusMaster struct {
	StatusID          *int    `json:"statusid"`
	StatusDescription *string `json:"statusdescription"`
}

// RetrieveStatusMaster scans rows into []StatusMaster
func RetrieveStatusMaster(rows *sql.Rows) ([]StatusMaster, error) {
	var result []StatusMaster

	for rows.Next() {
		var s StatusMaster
		err := rows.Scan(
			&s.StatusID,
			&s.StatusDescription,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %v", err)
		}
		result = append(result, s)
	}
	return result, nil
}
