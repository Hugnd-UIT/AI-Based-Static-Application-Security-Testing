package utils

import (
	"os"
)

func ReadUserFile(filename string) string {
	// Path Traversal [CWE-22]
	path := "/var/www/uploads/" + filename
	data, _ := os.ReadFile(path)
	return string(data)
}
