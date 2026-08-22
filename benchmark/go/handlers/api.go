package handlers

import (
	"fmt"
	"net/http"

	"benchmark/go/services"
	"benchmark/go/utils"
)

func GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	services.FetchUserById(id)
	fmt.Fprint(w, "User fetched")
}

func PingHost(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	utils.RunPing(ip)
	fmt.Fprint(w, "Ping executed")
}

func ReadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	data := utils.ReadUserFile(filename)
	fmt.Fprint(w, data)
}

func FetchResource(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	data := services.FetchHttp(url)
	fmt.Fprint(w, data)
}

func HashData(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	utils.EncryptToken()
	hash := utils.HashMD5(data)
	fmt.Fprint(w, hash)
}
