module benchmark/go

go 1.20

require (
	// Vulnerable Dependency: jwt-go (CVE-2020-26160)
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	
	// Vulnerable Dependency: gin (CVE-2020-28483)
	github.com/gin-gonic/gin v1.6.3
	
	// Vulnerable Dependency: old crypto library
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
)
