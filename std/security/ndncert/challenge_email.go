package ndncert

import (
	"fmt"

	"github.com/named-data/ndnd/std/types/optional"
)

type ChallengeEmail struct {
	// Email address to send the challenge to.
	Email string
	// Callback to get the code from the user.
	CodeCallback func(status string) string
}

// (AI GENERATED DESCRIPTION): Returns the constant name string KwEmail that identifies ChallengeEmail packets.
func (*ChallengeEmail) Name() string {
	return KwEmail
}

// (AI GENERATED DESCRIPTION): Generates the appropriate request parameters for an email‑based challenge, returning the email address on first contact or the user‑supplied code when a status indicates a required or incorrect code.
func (c *ChallengeEmail) Request(input ParamMap, status optional.Optional[string]) (ParamMap, error) {
	// Validate challenge configuration
	if len(c.Email) == 0 || c.CodeCallback == nil {
		return nil, fmt.Errorf("email challenge not configured")
	}

	// Initial request parameters
	if input == nil {
		return ParamMap{
			KwEmail: []byte(c.Email),
		}, nil
	}

	// Challenge response code
	if s := status.GetOr(""); s == "need-code" || s == "wrong-code" {
		code := c.CodeCallback(s)
		if code == "" {
			return nil, fmt.Errorf("no code provided")
		}

		return ParamMap{
			KwCode: []byte(code),
		}, nil
	}

	// Unknown status
	return nil, fmt.Errorf("unknown input to email challenge")
}
