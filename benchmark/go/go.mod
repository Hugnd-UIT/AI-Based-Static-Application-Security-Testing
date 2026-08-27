module benchmark/go

go 1.20

require (
	// Vulnerable Dependency: jwt-go (CVE-2020-26160)
	github.com/dgrijalva/jwt-go v3.2.0+incompatible

	// Vulnerable Dependency: gin (CVE-2020-28483)
	github.com/gin-gonic/gin v1.6.3

	// Vulnerable Dependency: old crypto library (CVE-2021-43565)
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad

	// Vulnerable Dependency: gogo/protobuf (CVE-2021-3121)
	github.com/gogo/protobuf v1.3.1

	// Vulnerable Dependency: x/text (CVE-2021-38561)
	golang.org/x/text v0.3.3
)
