package handlers

import (
	"io"
	"net/http"

	"benchmark/go/services"
)

func LoadData(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	services.DeserializeData(body)
	w.Write([]byte("Loaded"))
}

func FindNoSQL(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	services.ExecuteNoSQL(query)
	w.Write([]byte("Found"))
}
