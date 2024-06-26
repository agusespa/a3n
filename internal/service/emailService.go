package service

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/agusespa/a3n/internal/logger"
	"github.com/agusespa/a3n/internal/models"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type EmailService struct {
	Provider        string
	ApiKey          string
	ClientDomain    string
	SenderName      string
	SenderAddr      string
	Logo            string
	PrimaryColor    string
	SecondaryColor  string
	FontColor       string
	LinkColor       string
	BackgroundColor string
	Logger          *logger.Logger
}

type EmailContent struct {
	Logo            string
	Link            string
	BackgroundColor string
	FontColor       string
	LinkColor       string
}

func NewEmailService(config models.Config, key string, logger *logger.Logger) *EmailService {
	return &EmailService{
		Provider:        config.Api.Email.Provider,
		ApiKey:          key,
		ClientDomain:    config.Api.Client.Domain,
		SenderName:      config.Api.Email.Sender.Name,
		SenderAddr:      config.Api.Email.Sender.Address,
		Logo:            config.Branding.Logo,
		PrimaryColor:    config.Branding.Colors.Primary,
		SecondaryColor:  config.Branding.Colors.Secondary,
		FontColor:       config.Branding.Colors.Font,
		LinkColor:       config.Branding.Colors.Link,
		BackgroundColor: config.Branding.Colors.Background,
		Logger:          logger}
}

func (es *EmailService) SendEmail(email *mail.SGMailV3) {
	client := sendgrid.NewSendClient(es.ApiKey)
	response, err := client.Send(email)
	if err != nil {
		es.Logger.LogError(fmt.Errorf("failed to send email: %v", err.Error()))
	} else {
		es.Logger.LogInfo("email sent")
		es.Logger.LogDebug(fmt.Sprintf("email headers: %v", response))
	}
}

func (es *EmailService) BuildVerificationEmail(firstName, lastName, toAddr, token string) *mail.SGMailV3 {
	toName := firstName + " " + lastName

	subject := "Verify email address"

	link := es.ClientDomain + "/verify/" + token

	plainTextContent := "Follow this link to verify your email address: " + link

	emailTemplate := "<p>Follow this link to verify your email address:&nbsp;</p><a>" + link + "</a>"
	tmpl, err := template.ParseFiles("./config/assets/verify.html")
	if err == nil {
		content := EmailContent{
			Link:            link,
			Logo:            es.Logo,
			BackgroundColor: es.BackgroundColor,
			FontColor:       es.FontColor,
			LinkColor:       es.LinkColor,
		}

		var body bytes.Buffer
		err = tmpl.Execute(&body, content)
		if err != nil {
			es.Logger.LogDebug(fmt.Sprintf("failed to generate custom html template: %v", err.Error()))
		}
		emailTemplate = body.String()
	} else {
		es.Logger.LogDebug(fmt.Sprintf("failed to parse html template: %v", err.Error()))
	}

	from := mail.NewEmail(es.SenderName, es.SenderAddr)
	to := mail.NewEmail(toName, toAddr)

	return mail.NewSingleEmail(from, subject, to, plainTextContent, emailTemplate)
}
