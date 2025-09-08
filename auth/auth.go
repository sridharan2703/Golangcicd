// Package auth provides authentication and authorization functionality,
// including client IP validation, token validation, and stored procedure integration.
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
package auth

import (
	credentials "Hrmodule/dbconfig"
	"Hrmodule/utils"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	_ "github.com/go-sql-driver/mysql" // MySQL driver
)

// IsValid_IDFromRequest checks if the "token" query parameter is valid (alphanumeric only).
//
// Parameters:
//   - r: The HTTP request to extract and validate the "token" from.
//
// Returns:
//   - An error if the token contains invalid characters, otherwise nil.
// func IsValid_IDFromRequest(r *http.Request) error {
// 	idStr := r.URL.Query().Get("token")

// 	// Check for invalid characters
// 	for _, char := range idStr {
// 		if !unicode.IsLetter(char) && !unicode.IsDigit(char) {
// 			return errors.New("invalid character in TOKEN")
// 		}
// 	}

// 	return nil
// }

func IsValidIDFromRequest(r *http.Request) error {
	var token string

	// 1. Try to get token from the header
	token = r.Header.Get("token")

	// 2. Try to read from body only if it's POST and token is still empty
	if token == "" && r.Method == http.MethodPost {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return errors.New("unable to read request body")
		}
		// Restore the body so it can be read again later
		r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

		var bodyData struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(bodyBytes, &bodyData); err == nil {
			token = bodyData.Token
		}
	}

	// 3. Fallback to query string
	if token == "" {
		token = r.URL.Query().Get("token")
	}

	// 4. Token validation
	for _, char := range token {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) {
			return errors.New("invalid character in TOKEN")
		}
	}

	// Optional: match expected token
	// if token != "your_expected_token" {
	//     return errors.New("unauthorized")
	// }

	return nil
}

// LogRequestInfo logs the client's IP address and forwards the request to the given handler.
//
// Parameters:
//   - handler: The HTTP handler to wrap.
//
// Returns:
//   - A wrapped handler that logs the client IP before executing.
func LogRequestInfo(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		fmt.Printf("Client IP Address: %s\n", clientIP)
		handler(w, r)
	}
}

// ValidateAPI calls the stored procedure `API_Validation` to determine
// if the API access is valid, and logs the request and its result to a database.
//
// Parameters:
//   - APIName: The name of the API being accessed.
//   - clientIPAddress: The IP address of the requester.
//   - IDKey: The token or identifier used to validate the request.
//   - requestURL: The full URL of the incoming request.
//
// Returns:
//   - A boolean indicating if the request is valid.
//   - A status message returned from the stored procedure.
//   - An error if something goes wrong during validation or logging.
func ValidateAPI(APIName, clientIPAddress, IDKey, requestURL string) (bool, string, error) {

	// Step 6: Database connection and operation
	// Connection string for SQL Server
	connectionString := credentials.GetMySQLDatabase17()

	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		return false, "", fmt.Errorf("DB connection error: %v", err)
	}
	defer db.Close()

	stmt, err := db.Prepare("CALL API_Validation_New(?, ?, ?, @statusMessage)")
	if err != nil {
		return false, "", err
	}
	defer stmt.Close()

	_, err = stmt.Exec(APIName, clientIPAddress, IDKey)
	if err != nil {
		return false, "", err
	}

	var statusMessage string
	err = db.QueryRow("SELECT @StatusMessage").Scan(&statusMessage)
	if err != nil {
		return false, "", err
	}

	status := ""
	errorMessage := ""
	if statusMessage == "Success" {
		status = statusMessage
	} else {
		errorMessage = statusMessage
	}

	// Log the request and insert into Client_Request table
	_, err = db.Exec(`
        INSERT INTO Client_Request (
            Ip_Address, Request_Data, Response_Data,
            Status, Error, Request_On, Response_On, Updated_On
        )
        VALUES (?, ?, '', ?, ?, NOW(), NOW(), NOW())`,
		clientIPAddress, requestURL, status, errorMessage,
	)

	if err != nil {
		return false, "", err
	}

	return statusMessage == "Success", statusMessage, nil
}

// Responseset represents the standard API error response format.
type Responseset struct {
	Status  int      `json:"Status"`  // HTTP-like status code
	Message string   `json:"Message"` // Message describing the outcome
	Data    []string `json:"Data"`    // Additional data (usually empty for errors)
}

// HandleRequestforapiname_ipaddress_token validates a request by extracting relevant metadata (API name, IP address, token),
// invoking the `ValidateAPI` function, and returning an appropriate response.
//
// Parameters:
//   - w: The HTTP response writer.
//   - r: The HTTP request containing validation metadata.
//
// Returns:
//   - True if the request is authorized and passes all validations.
//   - False otherwise, and writes an error response directly to the client.
// func HandleRequestfor_apiname_ipaddress_token(w http.ResponseWriter, r *http.Request) bool {
// 	u, err := url.Parse(r.URL.String())
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return false
// 	}

// 	// Extract API name from URL path (e.g., /Facultydetails -> "Facultydetails")
// 	pathParts := strings.Split(u.Path, "/")
// 	var APIName string
// 	if len(pathParts) > 1 {
// 		APIName = pathParts[1]
// 	}

// 	clientIPAddress := strings.Split(r.RemoteAddr, ":")[0]

// 	// Extract token (IDKey) from query
// 	var IDKey string
// 	queryValues, err := url.ParseQuery(u.RawQuery)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return false
// 	}
// 	if idValues, ok := queryValues["token"]; ok && len(idValues) > 0 {
// 		IDKey = idValues[0]
// 	}

// 	requestURL := r.URL.String()

// 	isValid, statusMessage, err := ValidateAPI(APIName, clientIPAddress, IDKey, requestURL)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusForbidden)
// 		return false
// 	}

// 	switch statusMessage {
// 	case "Invalid_Key":
// 		return respondWithError(w, 400, "Invalid_Key")
// 	case "Invalid_APIName":
// 		return respondWithError(w, 401, "Invalid_APIName")
// 	case "Invalid_IPAddress":
// 		return respondWithError(w, 402, "Invalid_IPAddress")
// 	case "Inactive_APIName":
// 		return respondWithError(w, 403, "Inactive_APIName")
// 	case "Inactive_Vendor":
// 		return respondWithError(w, 404, "Inactive_Vendor")
// 	case "Inactive_Ip_Address":
// 		return respondWithError(w, 405, "Inactive_Ip_Address")
// 	case "UnauthorizedUser":
// 		return respondWithError(w, 406, "UnauthorizedUser")
// 	case "Invalid_RollNo":
// 		return respondWithError(w, 407, "UnauthorizedUser")
// 	}

// 	if !isValid {
// 		return respondWithError(w, http.StatusForbidden, statusMessage)
// 	}

// 	return true
// }

func HandleRequestfor_apiname_ipaddress_token(w http.ResponseWriter, r *http.Request) bool {
	// Extract the values from the request
	u, err := url.Parse(r.URL.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}

	// Extract the APIName from the URL path
	pathParts := strings.Split(u.Path, "/")
	var APIName string
	if len(pathParts) > 1 {
		APIName = pathParts[1] // Assuming "/Facultydetails" is part of the path
	}

	// Extract the clientIPAddress from the request
	clientIPAddress := strings.Split(r.RemoteAddr, ":")[0]

	// Extract the token from the header, body or query string
	var IDKey string

	// First check for token in header using 'X-Validation-Token'
	IDKey = r.Header.Get("token")

	// If the token is not in the header, check the body if it's a POST request
	if IDKey == "" && r.Method == http.MethodPost {
		var bodyData struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&bodyData); err == nil {
			IDKey = bodyData.Token
		}
	}

	// If the token is still not found, check the query string
	if IDKey == "" {
		queryValues := r.URL.Query()
		if idValues, ok := queryValues["token"]; ok && len(idValues) > 0 {
			IDKey = idValues[0]
		}
	}

	// Get the entire request URL as a string
	requestURL := r.URL.String()

	// Validate the API using the token, client IP, and APIName
	isValid, statusMessage, err := ValidateAPI(APIName, clientIPAddress, IDKey, requestURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return false
	}

	// Handle various API status messages
	switch statusMessage {
	case "Invalid_Key":
		return respondWithError(w, 400, "Invalid_Key")
	case "Invalid_APIName":
		return respondWithError(w, 401, "Invalid_APIName")
	case "Invalid_IPAddress":
		return respondWithError(w, 402, "Invalid_IPAddress")
	case "Inactive_APIName":
		return respondWithError(w, 403, "Inactive_APIName")
	case "Inactive_Vendor":
		return respondWithError(w, 404, "Inactive_Vendor")
	case "Inactive_Ip_Address":
		return respondWithError(w, 405, "Inactive_Ip_Address")
	case "UnauthorizedUser":
		return respondWithError(w, 406, "UnauthorizedUser")
	case "Invalid_RollNo":
		return respondWithError(w, 407, "Invalid_RollNo")
	}

	// If validation fails, return a forbidden error
	if !isValid {
		return respondWithError(w, http.StatusForbidden, statusMessage)
	}

	return true
}
// respondWithError writes an encrypted JSON error response to the client.
//
// It builds a structured error object (`Responseset`), marshals it to JSON,
// encrypts the response using AES-GCM, and sends it as a JSON object with an "encrypted" key.
//
// Parameters:
//   - w: The HTTP response writer.
//   - statusCode: The HTTP status code to send.
//   - message: The error message.
//
// Returns:
//   - false (for convenience use in calling code).
func respondWithError(w http.ResponseWriter, statusCode int, message string) bool {
	response := Responseset{
		Status:  statusCode,
		Message: message,
		Data:    []string{},
	}

	responseJSON, err := json.MarshalIndent(response, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}

	// Encrypt the error response
	encrypted, err := utils.Encrypt(responseJSON)
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return false
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"Data": encrypted,
	})

	return false
}
