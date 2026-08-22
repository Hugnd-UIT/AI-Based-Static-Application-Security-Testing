package services

import (
	"database/sql"
	"fmt"
)

func FetchUserById(id string) {
	db, _ := sql.Open("mysql", "user:pass@tcp(127.0.0.1:3306)/dbname")
	defer db.Close()

	// SQL Injection [CWE-89]
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", id)
	db.Query(query)
}
