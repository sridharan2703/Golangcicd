// Package modelscommon contains data structures and database access logic for the SessionData page.
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
package modelslogin

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

const MyQuerySessionData = `
SELECT id, session_id, department, username, user_id, employee_id, is_active, idletimeout, login_date, logout_date
FROM session_data
WHERE session_id = $1
`

// SessionDataStructure defines the structure of session_data
type SessionDataStructure struct {
	ID         *int64  `json:"id"`
	SessionID  *string `json:"session_id"`
	Department *string `json:"department"`
	Username   *string `json:"username"`
	UserID     *string `json:"user_id"`
	EmployeeID *string `json:"employee_id"`
	IsActive   *int    `json:"is_active"`
	IdleTime   *int64  `json:"idletimeout"`
	LoginDate  *string `json:"login_date"`
	LogoutDate *string `json:"logout_date"`
}

// RetrieveSessionData scans rows into SessionDataStructure slice
func RetrieveSessionData(rows *sql.Rows) ([]SessionDataStructure, error) {
	var sessionDataList []SessionDataStructure

	for rows.Next() {
		var s SessionDataStructure
		err := rows.Scan(
			&s.ID,
			&s.SessionID,
			&s.Department,
			&s.Username,
			&s.UserID,
			&s.EmployeeID,
			&s.IsActive,
			&s.IdleTime,
			&s.LoginDate,
			&s.LogoutDate,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %v", err)
		}
		sessionDataList = append(sessionDataList, s)
	}

	return sessionDataList, nil
}
