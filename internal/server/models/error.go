package models

type ErrorJSONResponse struct {
	Message map[string]map[string]string `json:"errors"`
}
