package ndncert

import (
	"fmt"
	"regexp"

	"github.com/named-data/ndnd/std/types/optional"
)

const (
	KwRecordName    = "record-name"
	KwExpectedValue = "expected-value"

	DNSPrefix = "_ndncert-challenge"
)

// ChallengeDns implements the DNS-01 challenge following Let's Encrypt practices.
// The challenge allows certificate requesters to prove domain ownership by creating
// a DNS TXT record containing a challenge token.
//
// Challenge Flow:
// 1. Requester provides domain name they want to validate
// 2. CA generates challenge token and responds with DNS record details
// 3. Requester creates TXT record at _ndncert-challenge.<domain> with challenge response
// 4. Requester confirms record is in place
// 5. CA performs DNS lookup to verify the TXT record exists
type ChallengeDns struct {
	// DomainCallback is called to get the domain name from the user.
	// It receives the challenge status for user prompting.
	DomainCallback func(status string) string

	// ConfirmationCallback is called to get confirmation from user that
	// they have created the required DNS record.
	// It receives the record details and status for user prompting.
	ConfirmationCallback func(recordName, expectedValue, status string) string

	// internal state for multi-step challenge
	domain        string
	recordName    string
	expectedValue string
}

// (AI GENERATED DESCRIPTION): Returns the predefined DNS keyword `KwDns`, identifying this challenge type.
func (*ChallengeDns) Name() string {
	return KwDns
}

// (AI GENERATED DESCRIPTION): Handles the DNS challenge flow by validating configuration, requesting domain and record details, invoking callbacks for user confirmation, and returning the appropriate parameter map for each challenge status.
func (c *ChallengeDns) Request(input ParamMap, status optional.Optional[string]) (ParamMap, error) {
	// Validate challenge configuration
	if c.DomainCallback == nil || c.ConfirmationCallback == nil {
		return nil, fmt.Errorf("dns challenge not configured")
	}

	statusStr := status.GetOr("")

	// Initial request: get domain from user
	if input == nil {
		c.domain = c.DomainCallback(statusStr)
		if c.domain == "" {
			return nil, fmt.Errorf("no domain provided")
		}

		if !isValidDomainName(c.domain) {
			return nil, fmt.Errorf("invalid domain name: %s", c.domain)
		}

		return ParamMap{
			KwDomain: []byte(c.domain),
		}, nil
	}

	// Handle different challenge statuses
	switch statusStr {
	case "need-record":
		// Extract DNS record information from input parameters
		if recordNameBytes, ok := input[KwRecordName]; ok {
			c.recordName = string(recordNameBytes)
		}
		if expectedValueBytes, ok := input[KwExpectedValue]; ok {
			c.expectedValue = string(expectedValueBytes)
		}

		// Get confirmation from user that they've created the DNS record
		confirmation := c.ConfirmationCallback(c.recordName, c.expectedValue, statusStr)
		if confirmation != "ready" {
			return nil, fmt.Errorf("expected 'ready' confirmation, got: %s", confirmation)
		}

		return ParamMap{
			KwConfirmation: []byte("ready"),
		}, nil

	case "wrong-record":
		// DNS verification failed, ask user to retry
		confirmation := c.ConfirmationCallback(c.recordName, c.expectedValue, statusStr)
		if confirmation != "ready" {
			return nil, fmt.Errorf("expected 'ready' confirmation, got: %s", confirmation)
		}

		return ParamMap{
			KwConfirmation: []byte("ready"),
		}, nil

	case "ready-for-validation":
		// Automatic validation phase - no user input needed
		return ParamMap{
			"verify": []byte("now"),
		}, nil

	default:
		return nil, fmt.Errorf("unknown DNS challenge status: %s", statusStr)
	}
}

// isValidDomainName validates domain name format according to RFC 1123
func isValidDomainName(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// RFC 1123 compliant hostname pattern
	domainPattern := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	return domainPattern.MatchString(domain)
}
