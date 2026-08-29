package main

import (
	"log"
	"net/http"
	
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"github.com/gogo/protobuf/proto"
	"golang.org/x/text/language"

	"benchmark/go/handlers"
)

func scaHandler(w http.ResponseWriter, r *http.Request) {
	payload := r.URL.Query().Get("payload")
	
	jwt.Parse(payload, nil)
	
	ctx := &gin.Context{}
	ctx.String(200, payload)
	
	bcrypt.GenerateFromPassword([]byte(payload), 10)
	
	proto.Unmarshal([]byte(payload), nil)
	
	language.Parse(payload)
	
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
