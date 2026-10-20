package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/named-data/ndnd/std/security/ndncert"
)

const emailCodeLength = 6
const emailCodeLifetime = 10 * time.Minute

const (
	emailCodeSaltKey = "email-code-salt"
	emailCodeHashKey = "email-code-hash"
)

type EmailSender interface {
	Send(to, subject, body string) error
}

type SMTPEmailSender struct {
	host     string
	port     int
	username string
	password string
	from     *mail.Address
	subject  string
}

func NewSMTPEmailSender(config EmailChallengeConfig, password string) (*SMTPEmailSender, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.SMTPUsername != "" && password == "" {
		return nil, fmt.Errorf("SMTP password environment variable is empty")
	}

	from, err := mail.ParseAddress(config.From)
	if err != nil {
		return nil, fmt.Errorf("invalid from address: %w", err)
	}
	port := config.SMTPPort
	if port == 0 {
		port = 587
	}
	subject := config.Subject
	if subject == "" {
		subject = "Your NDNCERT verification code"
	}

	return &SMTPEmailSender{
		host:     config.SMTPServer,
		port:     port,
		username: config.SMTPUsername,
		password: password,
		from:     from,
		subject:  subject,
	}, nil
}

func (s *SMTPEmailSender) Send(to, subject, body string) error {
	recipient, err := mail.ParseAddress(to)
	if err != nil || recipient.Address != to {
		return fmt.Errorf("invalid recipient email address")
	}
	if strings.ContainsAny(subject, "\r\n") || strings.ContainsRune(body, '\x00') {
		return fmt.Errorf("invalid email content")
	}
	if subject == "" {
		subject = s.subject
	}

	address := net.JoinHostPort(s.host, strconv.Itoa(s.port))
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to SMTP server: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return fmt.Errorf("set SMTP deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("create SMTP client: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); !ok {
		return fmt.Errorf("SMTP server does not support STARTTLS")
	}
	if err := client.StartTLS(&tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("start SMTP TLS: %w", err)
	}
	if s.username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.username, s.password, s.host)); err != nil {
			return fmt.Errorf("authenticate with SMTP server: %w", err)
		}
	}
	if err := client.Mail(s.from.Address); err != nil {
		return fmt.Errorf("set SMTP sender: %w", err)
	}
	if err := client.Rcpt(recipient.Address); err != nil {
		return fmt.Errorf("set SMTP recipient: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("start SMTP message: %w", err)
	}
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n",
		s.from.String(), recipient.String(), mime.QEncoding.Encode("UTF-8", subject), body)
	if _, err := io.WriteString(writer, message); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write SMTP message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish SMTP message: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("close SMTP session: %w", err)
	}
	return nil
}

type ChallengeEmailHandler struct {
	Sender       EmailSender
	Subject      string
	GenerateCode func() (string, error)
}

func (h *ChallengeEmailHandler) HandleChallenge(params ndncert.ParamMap, state *RequestState) (ndncert.ParamMap, string, error) {
	if state == nil {
		return nil, "", fmt.Errorf("request state is required")
	}

	switch state.Status {
	case StatusBeforeChallenge:
		if h.Sender == nil {
			return nil, "", fmt.Errorf("email sender is not configured")
		}
		emailBytes, ok := params[ndncert.KwEmail]
		if !ok || len(emailBytes) == 0 {
			return nil, "", fmt.Errorf("missing email address")
		}
		emailAddress := string(emailBytes)
		parsedEmail, err := mail.ParseAddress(emailAddress)
		if err != nil || parsedEmail.Address != emailAddress || strings.ContainsAny(emailAddress, "\r\n") {
			return nil, "", fmt.Errorf("invalid email address")
		}

		code, err := h.generateCode()
		if err != nil {
			return nil, "", fmt.Errorf("generate verification code: %w", err)
		}
		if len(code) != emailCodeLength || strings.Trim(code, "0123456789") != "" {
			return nil, "", fmt.Errorf("verification code generator returned an invalid code")
		}
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, "", fmt.Errorf("generate verification salt: %w", err)
		}
		body := fmt.Sprintf("Your NDNCERT verification code is: %s\nCA name: %s\nCertificate name: %s\n\nIf you did not request this certificate, you may ignore this message.",
			code, state.CaPrefix, state.RequestedCertName)
		subject := h.Subject
		if subject == "" {
			subject = "Your NDNCERT verification code"
		}
		if err := h.Sender.Send(emailAddress, subject, body); err != nil {
			return nil, "", fmt.Errorf("send verification email: %w", err)
		}

		if state.ChallengeState == nil {
			state.ChallengeState = make(map[string][]byte)
		}
		state.SetChallengeStateValue(emailCodeSaltKey, salt)
		state.SetChallengeStateValue(emailCodeHashKey, hashEmailCode(salt, code))
		state.Status = StatusChallenge
		state.UpdatedAt = time.Now()
		state.ExpiresAt = state.UpdatedAt.Add(emailCodeLifetime)
		return nil, "need-code", nil

	case StatusChallenge:
		codeBytes, ok := params[ndncert.KwCode]
		if !ok || len(codeBytes) == 0 {
			return nil, "need-code", nil
		}
		salt, hasSalt := state.GetChallengeStateValue(emailCodeSaltKey)
		expectedHash, hasHash := state.GetChallengeStateValue(emailCodeHashKey)
		if !hasSalt || !hasHash {
			return nil, "", fmt.Errorf("email challenge state is missing")
		}
		if time.Now().After(state.ExpiresAt) {
			state.MarkFailure("email code expired")
			clearEmailCode(state)
			return nil, "expired", nil
		}
		providedHash := hashEmailCode(salt, string(codeBytes))
		if subtle.ConstantTimeCompare(expectedHash, providedHash) == 1 && len(codeBytes) == emailCodeLength {
			state.Status = StatusSuccess
			state.UpdatedAt = time.Now()
			clearEmailCode(state)
			return nil, "", nil
		}
		if state.IncrementAttempts() {
			state.MarkFailure("email code attempts exhausted")
			clearEmailCode(state)
		}
		return nil, "wrong-code", nil

	default:
		return nil, "", fmt.Errorf("unexpected email challenge status %d", state.Status)
	}
}

func (h *ChallengeEmailHandler) generateCode() (string, error) {
	if h.GenerateCode != nil {
		return h.GenerateCode()
	}
	value, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", value.Int64()), nil
}

func hashEmailCode(salt []byte, code string) []byte {
	hash := sha256.New()
	_, _ = hash.Write(salt)
	_, _ = hash.Write([]byte(code))
	return hash.Sum(nil)
}

func clearEmailCode(state *RequestState) {
	delete(state.ChallengeState, emailCodeSaltKey)
	delete(state.ChallengeState, emailCodeHashKey)
}

var _ EmailSender = (*SMTPEmailSender)(nil)
