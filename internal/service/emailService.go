package service

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"path/filepath"

	"github.com/agusespa/a3n/internal/logger"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type EmailService interface {
	SendEmail(email *mail.SGMailV3)
	BuildVerificationEmail(firstName, lastName, toAddr, token string) *mail.SGMailV3
}

type DefaultEmailService struct {
	Client *sendgrid.Client
	Config ConfigService
	Logo   string
	Logger logger.Logger
}

type EmailContent struct {
	Logo            string
	Link            string
	BackgroundColor string
	FontColor       string
	LinkColor       string
}

func NewDefaultEmailService(config *DefaultConfigService, logger logger.Logger) *DefaultEmailService {
	return &DefaultEmailService{
		Client: sendgrid.NewSendClient(config.GetMailConfig().ApiKey),
		Config: config,
		Logo:   "https://github.com/agusespa/a3n/blob/main/config/assets/logo.png?raw=true",
		Logger: logger}
}

func (es *DefaultEmailService) SendEmail(email *mail.SGMailV3) {
	response, err := es.Client.Send(email)
	if err != nil {
		es.Logger.LogError(fmt.Errorf("failed to send email: %v", err.Error()))
	} else {
		es.Logger.LogInfo("email sent")
		es.Logger.LogDebug(fmt.Sprintf("email headers: %v", response))
	}
}

//go:embed templates/email_verify.html
var templatesFS embed.FS

func (es *DefaultEmailService) BuildVerificationEmail(firstName, lastName, toAddr, token string) *mail.SGMailV3 {
	toName := firstName + " " + lastName

	subject := "Verify email address"

	link := es.Config.GetDomain() + "/verify/" + token

	plainTextContent := "Follow this link to verify your email address: " + link

	emailTemplate := "<p>Follow this link to verify your email address:&nbsp;</p><a>" + link + "</a>"

	tmplPath := filepath.Join("templates", "email_verify.html")
	tmpl, err := template.ParseFS(templatesFS, tmplPath)
	if err == nil {
		content := EmailContent{
			Link: link,
			Logo: es.Logo,
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

	from := mail.NewEmail(es.Config.GetMailConfig().Sender.Name, es.Config.GetMailConfig().Sender.Address)
	to := mail.NewEmail(toName, toAddr)

	email := mail.NewSingleEmail(from, subject, to, plainTextContent, emailTemplate)
	return email
}
