package controllers

import (
	"gitlab.com/grey_scale/packetpacman/tests-and-analysis/clientsidetest.git/models"
)

func SendPackets(data []byte) models.MLServerResponse {
	/* req, _ := http.NewRequest("POST", "http://localhost:4000", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return MLServerResponse{Err: err}
	}
	serverResponse := models.MLServerResponse{}
	responseBody, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(responseBody, &serverResponse) */

	serverResponse := models.MLServerResponse{}
	return serverResponse

}
