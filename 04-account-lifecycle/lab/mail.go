package main

import (
	"fmt"
	"log"
	"net/smtp"
)

// sendMail delivers to Mailpit (the compose file's SMTP sink). Mailpit accepts
// everything and shows it in a web UI on http://localhost:8025 — so the lab's
// magic links and notifications are real emails you open in a browser, without
// sending anything to the internet.
func sendMail(to, subject, body string) {
	addr := env("SMTP_ADDR", "localhost:1025")
	from := "accounts@auth-lab.test"
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n", from, to, subject, body)
	if err := smtp.SendMail(addr, nil, from, []string{to}, []byte(msg)); err != nil {
		// Never fail the request because mail failed; log and move on.
		log.Printf("sendMail(%s): %v", to, err)
		return
	}
	log.Printf("mail -> %s: %s", to, subject)
}
