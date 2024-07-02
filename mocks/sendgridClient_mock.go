package mocks

import (
	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type MockSendGridClient struct {
	SendFunc func(email *mail.SGMailV3) (*rest.Response, error)
}

func (m *MockSendGridClient) Send(email *mail.SGMailV3) (*rest.Response, error) {
	return m.SendFunc(email)
}
