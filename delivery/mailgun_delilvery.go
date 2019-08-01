package delivery

import (
	"github.com/mailgun/mailgun-go"
)


type MailgunDelivery struct {
	impl  *mailgun.MailgunImpl
	from  string
}

func NewMailgunDelivery(domain string, apiKey string, from string) *MailgunDelivery {
	return &MailgunDelivery{impl:mailgun.NewMailgun(domain, apiKey), from:from}
}


func (m *MailgunDelivery) Send(destination, message string) error {
	msg := m.impl.NewMessage(m.from, "", message, destination)
	_, _, err := m.impl.Send(msg)
	return err
}



