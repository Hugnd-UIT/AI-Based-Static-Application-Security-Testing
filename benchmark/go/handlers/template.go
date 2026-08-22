package handlers

import (
	"fmt"
	"net/http"
)

func GreetUser(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// Cross-Site Scripting (XSS) [CWE-79]
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body>Hello %s</body></html>", name)
}
