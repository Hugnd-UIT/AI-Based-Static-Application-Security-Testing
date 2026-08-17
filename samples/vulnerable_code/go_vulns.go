package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
)

// Hardcoded Token
const GitHubToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

func main() {
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		db, _ := sql.Open("mysql", "user:pass@/dbname")
		username := r.URL.Query().Get("username")
		
		// SQL Injection
		query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
		rows, _ := db.Query(query)
		fmt.Fprintf(w, "Query executed: %v", rows)
		
		// XSS
		fmt.Fprintf(w, "<div>Hello " + username + "</div>")
	})

	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		
		// Command Injection
		cmd := exec.Command("sh", "-c", "ping -c 1 "+ip)
		out, _ := cmd.CombinedOutput()
		fmt.Fprintf(w, "Result: %s", out)
	})

	http.HandleFunc("/read", func(w http.ResponseWriter, r *http.Request) {
		filename := r.URL.Query().Get("file")
		
		// Path Traversal
		content, err := ioutil.ReadFile("/var/www/data/" + filename)
		if err != nil {
			http.Error(w, "File not found", 404)
			return
		}
		w.Write(content)
	})

	http.ListenAndServe(":8080", nil)
}
