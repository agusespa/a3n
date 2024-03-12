package models

type Config struct {
	DBUser          string `json:"db_user"`
	DBAddr          string `json:"db_addr"`
	DBName          string `json:"db_name"`
	EMAILProvider   string `json:"email_provider"`
	EMAILSenderAddr string `json:"email_sender_addr"`
	EMAILSenderName string `json:"email_sender_name"`
}
