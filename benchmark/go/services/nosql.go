package services

import (
	"fmt"
)

func ExecuteNoSQL(query string) {
	// NoSQL Injection [CWE-943]
	rawBson := fmt.Sprintf("{ \"$where\": \"this.name == '%s'\" }", query)
	_ = rawBson
}
