package service

import (
	"fmt"
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
	return &EmailService{Provider: config.EMAILProvider, ApiKey: key, SenderName: config.EMAILSenderName, SenderAddr: config.EMAILSenderAddr}
}

func (es *EmailService) SendEmail(toName, toAddr, subject, body, template string) error {
	from := mail.NewEmail(es.SenderName, es.SenderAddr)
	to := mail.NewEmail(toName, toAddr)
	plainTextContent := body
	htmlContent := template
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	client := sendgrid.NewSendClient(es.ApiKey)
	response, err := client.Send(message)

	// TODO
	if err != nil {
		log.Println(err)
	} else {
		fmt.Println(response.StatusCode)
		fmt.Println(response.Body)
		fmt.Println(response.Headers)
	}
	return nil
}
