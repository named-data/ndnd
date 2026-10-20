package server

import (
	"errors"
	"testing"
	"time"

	"github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/security/ndncert"
	"github.com/stretchr/testify/require"
)

type recordingEmailSender struct {
	to      string
	subject string
	body    string
	err     error
	calls   int
}

func (s *recordingEmailSender) Send(to, subject, body string) error {
	s.calls++
	s.to = to
	s.subject = subject
	s.body = body
	return s.err
}

func TestEmailChallengeFlow(t *testing.T) {
	sender := &recordingEmailSender{}
	state := NewRequestState([]byte("request"), encoding.Name{encoding.NewGenericComponent("example")})
	state.RequestedCertName = encoding.Name{encoding.NewGenericComponent("example"), encoding.NewGenericComponent("KEY")}
	handler := &ChallengeEmailHandler{
		Sender:       sender,
		Subject:      "Verification code",
		GenerateCode: func() (string, error) { return "042817", nil },
	}

	responseParams, status, err := handler.HandleChallenge(ndncert.ParamMap{
		ndncert.KwEmail: []byte("person@example.org"),
	}, state)
	require.NoError(t, err)
	require.Nil(t, responseParams)
	require.Equal(t, "need-code", status)
	require.Equal(t, StatusChallenge, state.Status)
	require.Equal(t, "person@example.org", sender.to)
	require.Equal(t, "Verification code", sender.subject)
	require.Contains(t, sender.body, "042817")
	require.NotContains(t, string(state.ChallengeState[emailCodeHashKey]), "042817")
	require.WithinDuration(t, time.Now().Add(emailCodeLifetime), state.ExpiresAt, time.Second)
	require.Equal(t, 1, sender.calls)

	responseParams, status, err = handler.HandleChallenge(ndncert.ParamMap{
		ndncert.KwCode: []byte("000000"),
	}, state)
	require.NoError(t, err)
	require.Nil(t, responseParams)
	require.Equal(t, "wrong-code", status)
	require.Equal(t, 1, state.ChallengeAttempts)
	require.Equal(t, StatusChallenge, state.Status)

	responseParams, status, err = handler.HandleChallenge(ndncert.ParamMap{
		ndncert.KwCode: []byte("042817"),
	}, state)
	require.NoError(t, err)
	require.Nil(t, responseParams)
	require.Empty(t, status)
	require.Equal(t, StatusSuccess, state.Status)
	require.NotContains(t, state.ChallengeState, emailCodeHashKey)
	require.Equal(t, 1, sender.calls)
}

func TestEmailChallengeWrongCodeLimit(t *testing.T) {
	handler := &ChallengeEmailHandler{
		Sender:       &recordingEmailSender{},
		GenerateCode: func() (string, error) { return "123456", nil },
	}
	state := NewRequestState([]byte("request"), encoding.Name{encoding.NewGenericComponent("example")})
	_, _, err := handler.HandleChallenge(ndncert.ParamMap{
		ndncert.KwEmail: []byte("person@example.org"),
	}, state)
	require.NoError(t, err)

	for attempt := 0; attempt < state.MaxChallengeAttempts; attempt++ {
		_, status, err := handler.HandleChallenge(ndncert.ParamMap{
			ndncert.KwCode: []byte("999999"),
		}, state)
		require.NoError(t, err)
		require.Equal(t, "wrong-code", status)
	}
	require.Equal(t, StatusFailure, state.Status)
	require.Equal(t, state.MaxChallengeAttempts, state.ChallengeAttempts)
	_, _, err = handler.HandleChallenge(ndncert.ParamMap{ndncert.KwCode: []byte("123456")}, state)
	require.Error(t, err)
}

func TestEmailChallengeRejectsInvalidAddress(t *testing.T) {
	sender := &recordingEmailSender{}
	handler := &ChallengeEmailHandler{Sender: sender}
	state := NewRequestState([]byte("request"), encoding.Name{encoding.NewGenericComponent("example")})

	_, _, err := handler.HandleChallenge(ndncert.ParamMap{
		ndncert.KwEmail: []byte("not-an-email\r\nBcc: victim@example.org"),
	}, state)
	require.Error(t, err)
	require.Equal(t, 0, sender.calls)
	require.Equal(t, StatusBeforeChallenge, state.Status)
}

func TestEmailChallengeMailerFailureDoesNotAdvanceState(t *testing.T) {
	sender := &recordingEmailSender{err: errors.New("SMTP unavailable")}
	handler := &ChallengeEmailHandler{
		Sender:       sender,
		GenerateCode: func() (string, error) { return "123456", nil },
	}
	state := NewRequestState([]byte("request"), encoding.Name{encoding.NewGenericComponent("example")})

	_, _, err := handler.HandleChallenge(ndncert.ParamMap{
		ndncert.KwEmail: []byte("person@example.org"),
	}, state)
	require.ErrorContains(t, err, "SMTP unavailable")
	require.Equal(t, StatusBeforeChallenge, state.Status)
	require.Empty(t, state.ChallengeState)
}

func TestSMTPEmailSenderRequiresPasswordForAuthenticatedSMTP(t *testing.T) {
	_, err := NewSMTPEmailSender(EmailChallengeConfig{
		SMTPServer:      "smtp.example.org",
		SMTPPort:        587,
		SMTPUsername:    "ndncert",
		SMTPPasswordEnv: "NDNCERT_SMTP_PASSWORD",
		From:            "NDN Certificate Robot <noreply@example.org>",
	}, "")
	require.ErrorContains(t, err, "password environment variable is empty")
}
