// Package routes defines CORS settings and registers HTTP routes for the API server.
//
// --- Creator's Info ---
//
// Creator: Sridharan
//
// Created On:07-07-2025
//
// Last Modified By: Sridharan
//
// Last Modified Date: 09-07-2025
package routes

import (
	"Hrmodule/auth"
	controllerscommon "Hrmodule/controllers/common"
	controllerslogin "Hrmodule/controllers/login"
	"fmt"
	"net/http"

	"github.com/rs/cors"
)

// Registerroutes sets up the HTTPS server with CORS support,
func Registerroutes() {
	// Create a new ServeMux router
	router := http.NewServeMux()

	// Register your API routes  Login api
	router.Handle("/HRldap", (http.HandlerFunc(controllerslogin.HandleLDAPAuth)))
	router.Handle("/Loginotp", (http.HandlerFunc(controllerslogin.InsertOTPHandler)))
	router.Handle("/Loginotpupdate", (http.HandlerFunc(controllerslogin.ValidateOTPHandler)))
	router.Handle("/Loginotpresend", (http.HandlerFunc(controllerslogin.InsertOTPresendHandler)))
	router.Handle("/SessionTimeout", auth.JwtMiddleware(http.HandlerFunc(controllerslogin.SessionTimeoutHandler)))
	router.Handle("/Sessiondata", auth.JwtMiddleware(http.HandlerFunc(controllerslogin.SessionData)))

	//Role api
	router.Handle("/Defaultrole", auth.JwtMiddleware(http.HandlerFunc(controllerscommon.DefaultRoleName)))
	router.Handle("/TaskInbox", auth.JwtMiddleware(http.HandlerFunc(controllerscommon.InboxTasksRole)))
	router.Handle("/Statusmaster", auth.JwtMiddleware(http.HandlerFunc(controllerscommon.StatusMaster)))
	router.Handle("/Inboxactivity", auth.JwtMiddleware(http.HandlerFunc(controllerscommon.NOCUpdateHandler)))

	// CORS configuration
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // Use specific origin(s) in production
		AllowedMethods:   []string{"POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	})

	// Apply CORS middleware to the router
	handler := c.Handler(router)

	fmt.Println("Server starting on port 5000")

	// TLS certificate and key
	certFile := "certificate.pem"
	keyFile := "key.pem"

	// Start the HTTPS server with CORS-enabled handler
	err := http.ListenAndServeTLS(":5000", certFile, keyFile, handler)
	if err != nil {
		fmt.Println("Server error:", err)
	}
}
