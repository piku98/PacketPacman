package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		var z interface{}
		json.NewDecoder(req.Body).Decode(&z)
		fmt.Println(z)
		rw.WriteHeader(200)
	})

	http.ListenAndServe(":4000", nil)

}
