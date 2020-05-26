package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		var z map[string]interface{}
		json.NewDecoder(req.Body).Decode(&z)
		if z["ProcessedPacket"].(map[string]interface{})["IPLayer"].(map[string]interface{})["SrcIP"].(string) == "192.168.0.3" {
			var resp struct {
				Flag    uint8
				IP      string
				Message string
				Err     error
			}
			resp.Flag = 3
			resp.IP = "192.168.0.3"
			resp.Message = "Danger IP"
			resp.Err = nil
			send, _ := json.Marshal(resp)
			fmt.Fprintf(rw, string(send))
		}
		rw.WriteHeader(200)
	})

	http.ListenAndServe(":4000", nil)

}
