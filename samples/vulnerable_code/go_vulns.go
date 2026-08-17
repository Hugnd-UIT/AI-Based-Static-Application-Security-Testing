package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

// Vulnerability 1: Server-Side Request Forgery (SSRF)
func fetchImage(w http.ResponseWriter, r *http.Request) {
	imageUrl := "https://example.com/" + r.URL.Query().Get("url")

	// Validate and sanitize the URL
	if !isValidURL(imageUrl) {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// [DATA FLOW] Source -> imageUrl -> GET request
	// SINK
	resp, err := http.Get(imageUrl)
	if err != nil {
		http.Error(w, "Failed to fetch image", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}

func isValidURL(url string) bool {
	// Implement URL validation logic here
	// For example, check if the URL is well-formed and uses HTTP/HTTPS
	// You can use the url.Parse function from the net/url package
	// and then check the Scheme field
	parsedURL, err := url.Parse(url)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return false
	}
	return true
}

func main() {
	http.HandleFunc("/fetch", fetchImage)
	fmt.Println("Server listening on :8080")
	http.ListenAndServeTLS(":8080", "/path/to/cert.pem", "/path/to/key.pem", nil)
}
