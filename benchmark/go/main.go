package main

import (
	"log"
	"net/http"

	"benchmark/go/handlers"
)

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

	log.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
}
