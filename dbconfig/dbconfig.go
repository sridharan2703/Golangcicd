
package credentials

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		panic("Failed to load .env: " + err.Error())
	}
}

// getDBConnectionString constructs and verifies a database connection string
// for the given driver (e.g., "postgres" or "mysql"). It opens and pings the
// database to ensure the connection is valid. It returns the connection string
// or panics on failure.
func getDBConnectionString(driver, server, user, password, database, port string) string {
	var connStr string

	switch driver {
	case "postgres":
		// ✅ Correct DSN format for lib/pq and gorm postgres driver
		connStr = fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
			server, user, password, database, port)
	case "mysql":
		connStr = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", user, password, server, port, database)
	default:
		panic("Unsupported DB driver: " + driver)
	}

	db, err := sql.Open(driver, connStr)
	if err != nil {
		panic("Failed to open DB connection: " + err.Error())
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		panic("Database connection failed: " + err.Error())
	}

	return connStr
}

// logMaskedConnection masks password and logs the connection string
func logMaskedConnection(connStr, password, dbType string) {
	safeConnStr := strings.Replace(connStr, password, "****", 1)
	log.Printf("%s connection: %s", dbType, safeConnStr)
}

// logFullyMaskedConnection masks all sensitive information in connection string
func logFullyMaskedConnection(connStr, password, user, host, database, dbType string) {
	safeConnStr := connStr

	// Replace sensitive information with ****
	safeConnStr = strings.Replace(safeConnStr, password, "****", -1)
	safeConnStr = strings.Replace(safeConnStr, user, "****", -1)
	safeConnStr = strings.Replace(safeConnStr, host, "****", -1)
	safeConnStr = strings.Replace(safeConnStr, database, "****", -1)

	log.Printf("%s connection: %s", dbType, safeConnStr)
}

// Postgres database
// Getdatabasehr returns Postgres connection string
func Getdatabasehr() string {
	serverhr := os.Getenv("serverhr")
	userhr := os.Getenv("userIdhr")
	passwordhr := os.Getenv("passwordhr")
	databasehr := os.Getenv("databasehr")
	porthr := os.Getenv("porthr")

	connStr := getDBConnectionString("postgres", serverhr, userhr, passwordhr, databasehr, porthr)

	// Choose one:
	// logMaskedConnection(connStr, password, "Postgres")  // Only mask password
	logFullyMaskedConnection(connStr, passwordhr, userhr, serverhr, databasehr, "Postgres") // Mask all sensitive info

	return connStr
}

// Getdatabasehr returns Postgres connection string
func Getdatabasemeivan() string {
	serverm := os.Getenv("serverm")
	userm := os.Getenv("userIdm")
	passwordm := os.Getenv("passwordm")
	databasem := os.Getenv("databasem")
	portm := os.Getenv("portm")
	log.Println(serverm)
	log.Println(userm)
	log.Println(passwordm)
	log.Println(databasem)
	log.Println(portm)
	connStr := getDBConnectionString("postgres", serverm, userm, passwordm, databasem, portm)

	// Choose one:
	// logMaskedConnection(connStr, password, "Postgres")  // Only mask password
	logFullyMaskedConnection(connStr, passwordm, userm, serverm, databasem, "Postgres") // Mask all sensitive info

	return connStr
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// GetMySQLDatabase17 returns MySQL connection string
func GetMySQLDatabase17() string {
	host := os.Getenv("DB_HOST")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	database := os.Getenv("DB_NAME")
	port := os.Getenv("DB_PORT")
	log.Println(host)
	log.Println(user)
	log.Println(password)
	log.Println(database)
	log.Println(port)
	connStr := getDBConnectionString("mysql", host, user, password, database, port)
	logFullyMaskedConnection(connStr, password, user, host, database, "MySQL")

	return connStr
}

// GetMySQLDatabase17HR returns MySQL HR connection string
func GetMySQLDatabase17HR() string {
	host := os.Getenv("DB_HOST_HR")
	user := os.Getenv("DB_USER_HR")
	password := os.Getenv("DB_PASSWORD_HR")
	database := os.Getenv("DB_NAME_HR")
	port := os.Getenv("DB_PORT_HR")

	connStr := getDBConnectionString("mysql", host, user, password, database, port)
	logFullyMaskedConnection(connStr, password, user, host, database, "MySQL HR")

	return connStr
}
