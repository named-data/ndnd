package ndncert

import (
	"errors"

	enc "github.com/named-data/ndnd/std/encoding"
)

// Keywords
const KwEmail = "email"
const KwPin = "pin"
const KwCode = "code"
const KwDns = "dns"
const KwDomain = "domain"
const KwConfirmation = "confirmation"

// Challenge Errors
var ErrChallengeBefore = errors.New("challenge before request")
var ErrChallengePending = errors.New("challenge pending")
var ErrChallengeFailed = errors.New("challenge failed")
var ErrChallengeStatusUnknown = errors.New("unknown challenge status")

// RequestCert Errors
type ErrSignerProbeMismatch struct {
	KeyName   enc.Name
	Suggested []enc.Name
}

// (AI GENERATED DESCRIPTION): Generates an error message stating that the supplied signer does not match any CA suggestion for the specified key name.
func (e ErrSignerProbeMismatch) Error() string {
	return "provided signer does not match any CA suggestion: " + e.KeyName.String()
}

var ErrNoKeySuggestions = errors.New("no key suggestions")
