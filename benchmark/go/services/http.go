package services

import (
	"io"
	"net/http"
)

func FetchHttp(url string) string {
	// Server-Side Request Forgery (SSRF) [CWE-918]
	resp, err := http.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}
