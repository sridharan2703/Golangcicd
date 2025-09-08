// This API serves as a core component of the Workflow-Human Resources Module system, functioning as a secure middleware layer that bridges the React-based frontend with the Microsoft SQL Server (MSSQL) backend.
//
// Once data is fetched from the database, it is encrypted, and sent to the frontend for display and user interaction.
//
// This middleware design promotes separation of concerns, enhances security through built-in authentication and encryption, and ensures smooth communication between the user interface and the underlying data infrastructure that powers Human Resources workflows and operations.
package main

import (
"Hrmodule/routes"
)

// main is the entry point of the application.
// It calls Registerroutes to bind API endpoints and start the server.
func main() {
	routes.Registerroutes()
}
