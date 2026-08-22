package handlers

import (
	"net/http"
)

func LoginRedirect(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	// Open Redirect [CWE-601]
	http.Redirect(w, r, url, http.StatusFound)
}
