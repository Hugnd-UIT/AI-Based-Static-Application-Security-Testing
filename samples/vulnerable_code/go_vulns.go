package main

import (
	"database/sql"
	"net/http"
	"os/exec"
)

func updateSettings(w http.ResponseWriter, r *http.Request) {
    // Zero-day IDOR
	db, _ := sql.Open("mysql", "user:pass@/dbname")
	userID := r.URL.Query().Get("user_id")
	setting := r.URL.Query().Get("setting")
	db.Exec("UPDATE settings SET value = ? WHERE user_id = ?", setting, userID)
}

func ping(w http.ResponseWriter, r *http.Request) {
    // Known vuln: Command Injection
	ip := r.URL.Query().Get("ip")
	cmd := exec.Command("ping", "-c", "1", ip)
	cmd.Run()
}
