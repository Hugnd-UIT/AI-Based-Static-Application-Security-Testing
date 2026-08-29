package main

import (
	"log"
	"net/http"
	
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/text/language"

	"benchmark/go/handlers"
)

func scaHandler(w http.ResponseWriter, r *http.Request) {
	payload := r.URL.Query().Get("payload")
	
	// CVE-2020-26160 (jwt-go)
	jwt.ParseUnverified(payload, &jwt.StandardClaims{})
	
	// CVE-2020-28483 (gin)
	ctx := &gin.Context{Request: r}
	_ = ctx.ClientIP()
	
	// CVE-2021-43565 (golang.org/x/crypto/ssh)
	golang.org.x.crypto.ssh.ParsePublicKey([]byte(payload))
	
	// CVE-2021-3121 (gogo/protobuf)
	var m proto.Message
	proto.Unmarshal([]byte(payload), m)
	
	// CVE-2021-38561 (text/language)
	language.ParseExt(payload)
	
	w.Write([]byte("OK"))
}

func main() {
	http.HandleFunc("/user", handlers.GetUser)
	http.HandleFunc("/ping", handlers.PingHost)
	http.HandleFunc("/read", handlers.ReadFile)
	http.HandleFunc("/fetch", handlers.FetchResource)
	http.HandleFunc("/hash", handlers.HashData)
	http.HandleFunc("/greet", handlers.GreetUser)
	http.HandleFunc("/redirect", handlers.LoginRedirect)
	http.HandleFunc("/load", handlers.LoadData)
	http.HandleFunc("/find", handlers.FindNoSQL)
	http.HandleFunc("/sca", scaHandler)

	log.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
}
