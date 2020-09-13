package controllers

type MLServerResponse struct {
	Flag    uint8
	IP      string
	Message string
	Err     error
}

func SendPackets(data []byte) MLServerResponse {
	/* req, _ := http.NewRequest("POST", "http://localhost:4000", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return MLServerResponse{Err: err}
	}
	serverResponse := MLServerResponse{}
	responseBody, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(responseBody, &serverResponse) */

	serverResponse := MLServerResponse{}
	return serverResponse

}
