package main

import (
	"fmt"
	"log"
	"net/smtp"
	"sync/atomic"
)

// Two delivery channels, deliberately modelled differently.
//
// email -> Mailpit, a real SMTP sink you can open at http://localhost:8025.
// sms   -> a fake carrier that only logs, but METERS: every send costs money.
//          That meter is the point of the toll-fraud demo; in production this is
//          the line item that shows up on the telecom invoice, not in your logs.

var smsSent int64
var smsCostMicros int64

const smsCostPerMsgMicros = 7500 // ~$0.0075/msg, a plausible international rate

func deliver(channel, to, subject, body string) {
	switch channel {
	case "sms":
		atomic.AddInt64(&smsSent, 1)
		atomic.AddInt64(&smsCostMicros, smsCostPerMsgMicros)
		log.Printf("SMS -> %s: %s", to, body)
	default:
		sendMail(to, subject, body)
	}
}

func sendMail(to, subject, body string) {
	addr := env("SMTP_ADDR", "localhost:1025")
	from := "accounts@auth-lab.test"
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n", from, to, subject, body)
	if err := smtp.SendMail(addr, nil, from, []string{to}, []byte(msg)); err != nil {
		// Never fail the login request because mail failed; log and move on.
		log.Printf("sendMail(%s): %v", to, err)
		return
	}
	log.Printf("mail -> %s: %s", to, subject)
}
