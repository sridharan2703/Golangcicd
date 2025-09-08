// Package controllerslogin provides LDAP-based authentication,
// encrypted credential validation, session management,
// and JWT token generation for secure login workflows.
//
// --- Creator's Info ---
//
// Creator: Sridharan
//
// Created On: 26-08-2025
//
// Last Modified By: Sridharan
//
// Last Modified Date: 26-08-2025
package controllerslogin

import (
	"Hrmodule/auth"
	credentials "Hrmodule/dbconfig"
	"Hrmodule/utils"
	"bytes"
	"crypto/aes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

type AuthRequest struct {
	Token    string `json:"Hrtoken"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Valid        bool   `json:"valid"`
	UserId       string `json:"userId,omitempty"`
	Username     string `json:"username,omitempty"`
	EmployeeId   string `json:"EmployeeId"`
	MobileNumber string `json:"MobileNumber"`
	Token        string `json:"token,omitempty"`
}

type AuthResponsefalse struct {
	Valid    bool   `json:"valid"`
	Username string `json:"username,omitempty"`
	Error    string `json:"error,omitempty"`
}

var jwtSecret []byte
var encryptionKey string

func init() {
	// Optional: load from .env file (for development)
	_ = godotenv.Load()

	jwtKey := os.Getenv("JWT_SECRET_KEY")
	if jwtKey == "" {
		panic("JWT_SECRET_KEY environment variable not set")
	}
	jwtSecret = []byte(jwtKey)

	encryptionKey = os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		panic("ENCRYPTION_KEY environment variable not set")
	}
}

// Create JWT Token
func generateJWT(userId, username, employeeId string) (string, error) {
	claims := jwt.MapClaims{
		"userId":     userId,
		"username":   username,
		"employeeId": employeeId,
		"exp":        time.Now().Add(time.Hour * 2).Unix(), // Token expires in 2 hours
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Helper function to check if string is hex-encoded
func isHexString(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// decryptData decrypts hex-encoded encrypted data using AES
func decryptData(encryptedData, key string) (string, error) {
	keyBytes := []byte(key)
	encryptedBytes, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("invalid hex encoding: %v", err)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	if len(encryptedBytes)%aes.BlockSize != 0 {
		return "", fmt.Errorf("encrypted data is not a multiple of the block size")
	}

	decrypted := make([]byte, len(encryptedBytes))
	for i := 0; i < len(encryptedBytes); i += aes.BlockSize {
		block.Decrypt(decrypted[i:i+aes.BlockSize], encryptedBytes[i:i+aes.BlockSize])
	}

	// Remove padding
	decrypted = PKCS5Unpad(decrypted)

	return string(decrypted), nil
}

// decryptDataStrict only accepts encrypted (hex-encoded) data
func decryptDataStrict(data, key string) (string, error) {
	// Check if data is hex-encoded (encrypted)
	if !isHexString(data) {
		return "", fmt.Errorf("invalid input: data must be encrypted (hex-encoded)")
	}

	// Only decrypt if it's valid hex
	return decryptData(data, key)
}

// validateEncryptedCredentials validates that both username and password are encrypted
func validateEncryptedCredentials(username, password string) (bool, string) {
	if username == "" || password == "" {
		return false, "Missing username or password"
	}

	if !isHexString(username) {
		return false, "Invalid username format - must be encrypted (hex-encoded)"
	}

	if !isHexString(password) {
		return false, "Invalid password format - must be encrypted (hex-encoded)"
	}

	return true, ""
}

// PKCS5Unpad removes padding from decrypted data
func PKCS5Unpad(data []byte) []byte {
	pad := int(data[len(data)-1])
	return data[:len(data)-pad]
}

// HandleLDAPAuth processes an HTTP request for LDAP authentication.
// It ONLY accepts encrypted credentials, validates them against LDAP servers (staff, faculty, project),
// inserts session data into the database, and returns an encrypted JSON response with JWT token.
func HandleLDAPAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed. Use POST.", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Parse request body
	var req AuthRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		http.Error(w, "Invalid JSON input", http.StatusBadRequest)
		return
	}

	// Set token in the header for auth functions
	r.Header.Set("token", req.Token)

	// handles sp validation
	authorized := auth.HandleRequestfor_apiname_ipaddress_token(w, r)
	if !authorized {
		return
	}

	// For getting clientipaddress
	loggedHandler := auth.LogRequestInfo(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// For id parameter
		// For id parameter
		err := auth.IsValidIDFromRequest(r)
		if err != nil {
			http.Error(w, "Invalid Token provided", http.StatusBadRequest)
			return
		}

		// // Decode JSON body into AuthRequest struct
		// var req AuthRequest
		// if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// 	http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		// 	return
		// }

		username := req.Username
		password := req.Password

		// Validate that credentials are encrypted
		valid, errorMsg := validateEncryptedCredentials(username, password)
		if !valid {
			log.Printf("Validation error: %s", errorMsg)
			resp := AuthResponsefalse{
				Valid: false,
				Error: errorMsg,
			}
			jsonResponse, err := json.Marshal(resp)
			if err != nil {
				http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
				return
			}
			encrypted, err := utils.Encrypt(jsonResponse)
			if err != nil {
				http.Error(w, "Encryption failed", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"Data": encrypted,
			})
			return
		}

		// Print encrypted credentials for debugging
		fmt.Println("Encrypted username:", username)
		fmt.Println("Encrypted password:", password)

		// Decrypt username and password - ONLY accept encrypted data
		// key := "7xPz!qL3vNc#eRb9Wm@f2Zh8Kd$gYp1B"

		fmt.Println("Decryption key:", encryptionKey)

		// Decrypt username using strict decryption
		decodedUsername, err := decryptDataStrict(username, encryptionKey)
		if err != nil {
			log.Printf("Error decrypting username: %v", err)
			resp := AuthResponsefalse{
				Valid:    false,
				Username: "Invalid",
				Error:    "Username decryption failed",
			}
			jsonResponse, err := json.Marshal(resp)
			if err != nil {
				http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
				return
			}
			encrypted, err := utils.Encrypt(jsonResponse)
			if err != nil {
				http.Error(w, "Encryption failed", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"Data": encrypted,
			})
			return
		}

		fmt.Println("Decrypted Username:", decodedUsername)

		// Decrypt password using strict decryption
		decodedPassword, err := decryptDataStrict(password, encryptionKey)
		if err != nil {
			log.Printf("Error decrypting password: %v", err)
			resp := AuthResponsefalse{
				Valid:    false,
				Username: "Invalid",
				Error:    "Password decryption failed",
			}
			jsonResponse, err := json.Marshal(resp)
			if err != nil {
				http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
				return
			}
			encrypted, err := utils.Encrypt(jsonResponse)
			if err != nil {
				http.Error(w, "Encryption failed", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"Data": encrypted,
			})
			return
		}
		fmt.Println("Decrypted Password:", decodedPassword)

		// Continue with LDAP authentication using decodedUsername and decodedPassword...
		dn := "cn=academicbind,ou=bind,dc=ldap,dc=iitm,dc=ac,dc=in"
		pass := "1@iIL~0K"
		ldapUserFilter := "(&(objectclass=*)(uid=" + decodedUsername + "))"
		searchBaseStaff := "ou=staff,ou=people,dc=ldap,dc=iitm,dc=ac,dc=in"
		searchBaseFaculty := "ou=faculty,ou=people,dc=ldap,dc=iitm,dc=ac,dc=in"
		searchbase_project := "ou=project,ou=employee,dc=ldap,dc=iitm,dc=ac,dc=in"
		//	searchBaseStudent := "ou=student,dc=ldap,dc=iitm,dc=ac,dc=in"  //comment for later use
		//fmt.Println(decodedUsername)
		ldapURL := "ldap://ldap.iitm.ac.in:389"

		conn, err := ldap.DialURL(ldapURL)
		if err != nil {
			log.Printf("Failed to connect to LDAP server: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		err = conn.Bind(dn, pass)
		if err != nil {
			log.Printf("Server DN Bind Failed: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		var ou string
		var responseSent bool

		performSearch := func(searchBase, userType string) {
			req := ldap.NewSearchRequest(
				searchBase,
				ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				ldapUserFilter,
				nil,
				nil,
			)

			sr, err := conn.Search(req)
			if err != nil {
				log.Printf("Search Failed: %v", err)
				return
			}

			for _, entry := range sr.Entries {
				dn := entry.DN
				bindCredentials := decodedPassword

				if dn != "" && bindCredentials != "" {
					err = conn.Bind(dn, bindCredentials)
					if err != nil {
						log.Printf("%s Bind Failed: %v", userType, err)
					} else {
						log.Printf("%s Bind Successful", userType)
						ou = userType

						if !responseSent {
							responseSent = true

							userId := generateUserId()
							employeeId, mobileNumber, err := getEmployeeInfo(decodedUsername)

							if err != nil {
								log.Printf("Error retrieving employee info: %v", err)
								http.Error(w, "Internal Server Error", http.StatusInternalServerError)
								return
							}

							err = insertSessionData(userId, decodedUsername, ou, employeeId)
							if err != nil {
								log.Printf("Error inserting session data: %v", err)
								http.Error(w, "Internal Server Error", http.StatusInternalServerError)
								return
							}

							// Generate JWT
							tokenString, err := generateJWT(userId, decodedUsername, employeeId)
							if err != nil {
								log.Printf("Error generating JWT: %v", err)
								http.Error(w, "Internal Server Error", http.StatusInternalServerError)
								return
							}

							resp := AuthResponse{
								Valid:        true,
								UserId:       userId,
								Username:     decodedUsername,
								EmployeeId:   employeeId,   // ✅ now included
								MobileNumber: mobileNumber, // ✅ added
								Token:        tokenString,  // ✅ JWT token added
							}

							jsonResponse, err := json.Marshal(resp)
							if err != nil {
								http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
								return
							}
							encrypted, err := utils.Encrypt(jsonResponse)
							if err != nil {
								http.Error(w, "Encryption failed", http.StatusInternalServerError)
								return
							}
							w.Header().Set("Content-Type", "application/json")
							_ = json.NewEncoder(w).Encode(map[string]string{
								"Data": encrypted,
							})

						}
					}
				} else {
					log.Println("DN or password is null or undefined")
				}
			}
		}

		// Check staff first
		performSearch(searchBaseStaff, "staff")
		// If not staff, check faculty
		performSearch(searchBaseFaculty, "faculty")
		// If not faculty, check project
		performSearch(searchbase_project, "project")
		// If not faculty, check student
		//		performSearch(searchBaseStudent, "student")  //comment for later use

		if ou == "" {
			log.Println("LDAP Entries Mismatch")
			if !responseSent {
				responseSent = true
				resp := AuthResponse{
					Valid:    false,
					Username: decodedUsername,
				}

				jsonResponse, err := json.Marshal(resp)
				if err != nil {
					http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
					return
				}
				encrypted, err := utils.Encrypt(jsonResponse)
				if err != nil {
					http.Error(w, "Encryption failed", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"Data": encrypted,
				})

			} else {
				// If LDAP authentication succeeds for any user type,
				// reset the responseSent flag to false
				responseSent = false
			}
		}

	}))
	loggedHandler.ServeHTTP(w, r)
}

// generateUserId creates and returns a new UUID string.
func generateUserId() string {
	return uuid.New().String()
}

// Add this new function to handle existing active sessions
func updatePreviousActiveSessions(employeeId string) error {
	// Connection string for postgres Server
	connectionString := credentials.Getdatabasemeivan()

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return fmt.Errorf("DB open error: %v", err)
	}
	defer db.Close()

	// Update all active sessions for this employee_id
	query := `UPDATE Session_Data 
			  SET Is_Active = '0', 
				  idletimeout = '1', 
				  Logout_Date = NOW() 
			  WHERE Employee_id = $1 AND Is_Active = '1'`

	result, err := db.Exec(query, employeeId)
	if err != nil {
		return fmt.Errorf("failed to update previous sessions: %v", err)
	}

	// Log how many rows were affected (optional)
	rowsAffected, err := result.RowsAffected()
	if err == nil {
		log.Printf("Updated %d previous active sessions for employee %s", rowsAffected, employeeId)
	}

	return nil
}

// Updated insertSessionData function
func insertSessionData(userId, username, ou, employeeId string) error {
	// First, update any existing active sessions for this employee
	err := updatePreviousActiveSessions(employeeId)
	if err != nil {
		log.Printf("Warning: Failed to update previous sessions: %v", err)
		// You can decide whether to continue or return error here
		// For now, we'll continue with the login process
	}

	// Connection string for postgres Server
	connectionString := credentials.Getdatabasemeivan()

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return fmt.Errorf("DB open error: %v", err)
	}
	defer db.Close()

	// Insert new session record
	query := `INSERT INTO Session_Data 
		(Session_Id, Logout_Date, Username, Is_Active, idletimeout, Department, User_id, Employee_id, Login_Date) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`

	_, err = db.Exec(query, userId, nil, username, "1", "0", ou, userId, employeeId)
	if err != nil {
		return err
	}

	log.Printf("New session created for employee %s with session ID %s", employeeId, userId)
	return nil
}

// getEmployeeInfo queries employeebasicinfo table to retrieve EmployeeId and MobileNumber.
func getEmployeeInfo(username string) (string, string, error) {
	// Connection string for postgres Server
	connectionString := credentials.Getdatabasehr()

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return "", "", err
	}
	defer db.Close()

	// ✅ Fetch both EmployeeId and Mobilenumber
	query := `SELECT EmployeeId, Mobilenumber FROM employeebasicinfo WHERE LoginName = $1`
	row := db.QueryRow(query, username)

	var employeeId, mobileNumber string
	err = row.Scan(&employeeId, &mobileNumber)
	if err != nil {
		return "", "", err
	}

	return employeeId, mobileNumber, nil
}
