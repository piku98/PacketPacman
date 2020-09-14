package models

type MLServerResponse struct {
	Flag    uint8
	IP      string
	Message string
	Err     error
}
