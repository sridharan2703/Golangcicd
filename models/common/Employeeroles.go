// Package models contains data structures and database access logic for the DefaultRoleName page.
//
// --- Creator's Info ---
//
// Creator: Sridharan
//
// Created On:30-07-2025
//
// Last Modified By: Sivabala
//
// Last Modified Date: 30-07-2025
//
// Path:Login Page
package modelscommon

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

const MyQueryDefaultRoleName = `
SELECT B.USERID, A.USERNAME, D.ROLENAME, B.IsActive 
FROM USERMASTER A 
JOIN ORGUNITUSERMAPPING B ON A.USERID = B.USERID
JOIN ORGUNITROLEMAPPING C ON B.RoleMapId = C.ROLEMAPID
JOIN ROLEMASTER D ON C.ROLEID = D.ROLEID
WHERE A.UserName = $1
AND B.IsActive IN ('1','0')
ORDER BY B.UPDATEDON ASC
`

// DefaultRoleNamestructure defines the structure of DefaultRoleName
type DefaultRoleNamestructure struct {
	USERID   *string `json:"UserID"`
	USERNAME *string `json:"Username"`
	ROLENAME *string `json:"RoleName"`
	IsActive *string `json:"IsActive"`
}

// RetrieveDefaultRoleName scans rows into DefaultRoleNamestructure slice
func RetrieveDefaultRoleName(rows *sql.Rows) ([]DefaultRoleNamestructure, error) {
	var DefaultRoleNameapi []DefaultRoleNamestructure

	for rows.Next() {
		var DRN DefaultRoleNamestructure
		err := rows.Scan(
			&DRN.USERID,
			&DRN.USERNAME,
			&DRN.ROLENAME,
			&DRN.IsActive,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %v", err)
		}
		DefaultRoleNameapi = append(DefaultRoleNameapi, DRN)
	}

	return DefaultRoleNameapi, nil
}
