package service

import (
	"log"

	"github.com/agusespa/a3n/internal/models"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type EmailService struct {
	Provider   string
	ApiKey     string
	SenderName string
	SenderAddr string
}

func NewEmailService(config models.Config, key string) *EmailService {
	return &EmailService{Provider: config.Email.Provider, ApiKey: key, SenderName: config.Email.Sender.Name, SenderAddr: config.Email.Sender.Address}
}

func (es *EmailService) SendEmail(email *mail.SGMailV3) error {
	client := sendgrid.NewSendClient(es.ApiKey)
	response, err := client.Send(email)
	// TODO: handle error logs better?
	if err != nil {
		log.Printf("email error: %v", err.Error())
	}
	log.Printf("email response: %v", response)
	return err
}

func (es *EmailService) BuildEmail(toName, toAddr, subject, body, template string) *mail.SGMailV3 {
	from := mail.NewEmail(es.SenderName, es.SenderAddr)
	to := mail.NewEmail(toName, toAddr)
	plainTextContent := body
	htmlContent := template
	return mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
}
