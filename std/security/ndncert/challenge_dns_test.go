package ndncert_test

import (
	"testing"

	"github.com/named-data/ndnd/std/security/ndncert"
	"github.com/named-data/ndnd/std/types/optional"
)

// (AI GENERATED DESCRIPTION): Ensures that the `ChallengeDns.Name()` method returns the expected string `"dns"`.
func TestChallengeDns_Name(t *testing.T) {
	challenge := &ndncert.ChallengeDns{}
	if challenge.Name() != "dns" {
		t.Errorf("Expected challenge name 'dns', got '%s'", challenge.Name())
	}
}

// (AI GENERATED DESCRIPTION): TestChallengeDns_InitialRequest verifies that ChallengeDns.Request correctly invokes the DomainCallback and returns the resulting domain as a parameter in the returned map.
func TestChallengeDns_InitialRequest(t *testing.T) {
	domainCalled := false
	expectedDomain := "example.com"

	challenge := &ndncert.ChallengeDns{
		DomainCallback: func(status string) string {
			domainCalled = true
			return expectedDomain
		},
		ConfirmationCallback: func(recordName, expectedValue, status string) string {
			return "ready"
		},
	}

	params, err := challenge.Request(nil, optional.Optional[string]{})
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !domainCalled {
		t.Error("Expected domain callback to be called")
	}

	if string(params["domain"]) != expectedDomain {
		t.Errorf("Expected domain parameter '%s', got '%s'", expectedDomain, string(params["domain"]))
	}
}

// (AI GENERATED DESCRIPTION): Verifies that `ChallengeDns.Request` returns an error when the domain callback supplies an invalid domain name.
func TestChallengeDns_InvalidDomain(t *testing.T) {
	challenge := &ndncert.ChallengeDns{
		DomainCallback: func(status string) string {
			return "invalid..domain" // Invalid domain format
		},
		ConfirmationCallback: func(recordName, expectedValue, status string) string {
			return "ready"
		},
	}

	_, err := challenge.Request(nil, optional.Optional[string]{})
	if err == nil {
		t.Error("Expected error for invalid domain, got none")
	}
}

// (AI GENERATED DESCRIPTION): Tests that a ChallengeDns instance correctly handles a “need‑record” status by invoking the confirmation callback with the expected record name, value, and status, and returns the callback’s result in the output parameters.
func TestChallengeDns_NeedRecordStatus(t *testing.T) {
	confirmationCalled := false
	expectedRecordName := "_ndncert-challenge.example.com"
	expectedValue := "test-token-hash"

	challenge := &ndncert.ChallengeDns{
		DomainCallback: func(status string) string {
			return "example.com"
		},
		ConfirmationCallback: func(recordName, expValue, status string) string {
			confirmationCalled = true
			if recordName != expectedRecordName {
				t.Errorf("Expected record name '%s', got '%s'", expectedRecordName, recordName)
			}
			if expValue != expectedValue {
				t.Errorf("Expected value '%s', got '%s'", expectedValue, expValue)
			}
			if status != "need-record" {
				t.Errorf("Expected status 'need-record', got '%s'", status)
			}
			return "ready"
		},
	}

	// Simulate input parameters from CA response
	input := ndncert.ParamMap{
		"record-name":    []byte(expectedRecordName),
		"expected-value": []byte(expectedValue),
	}

	status := optional.Some("need-record")
	params, err := challenge.Request(input, status)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !confirmationCalled {
		t.Error("Expected confirmation callback to be called")
	}

	if string(params["confirmation"]) != "ready" {
		t.Errorf("Expected confirmation parameter 'ready', got '%s'", string(params["confirmation"]))
	}
}

// (AI GENERATED DESCRIPTION): Tests that ChallengeDns.Request correctly passes a “wrong-record” status to the ConfirmationCallback and returns the callback’s result as the “confirmation” parameter.
func TestChallengeDns_WrongRecordStatus(t *testing.T) {
	challenge := &ndncert.ChallengeDns{
		DomainCallback: func(status string) string {
			return "example.com"
		},
		ConfirmationCallback: func(recordName, expectedValue, status string) string {
			if status != "wrong-record" {
				t.Errorf("Expected status 'wrong-record', got '%s'", status)
			}
			return "ready"
		},
	}

	input := ndncert.ParamMap{
		"record-name":    []byte("_ndncert-challenge.example.com"),
		"expected-value": []byte("test-token-hash"),
	}

	status := optional.Some("wrong-record")
	params, err := challenge.Request(input, status)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if string(params["confirmation"]) != "ready" {
		t.Errorf("Expected confirmation parameter 'ready', got '%s'", string(params["confirmation"]))
	}
}

// (AI GENERATED DESCRIPTION): Tests that the ChallengeDns.Request method returns a 'verify' parameter set to “now” when called with a status of “ready-for-validation”.
func TestChallengeDns_ReadyForValidationStatus(t *testing.T) {
	challenge := &ndncert.ChallengeDns{
		DomainCallback: func(status string) string {
			return "example.com"
		},
		ConfirmationCallback: func(recordName, expectedValue, status string) string {
			return "ready"
		},
	}

	input := ndncert.ParamMap{}
	status := optional.Some("ready-for-validation")
	params, err := challenge.Request(input, status)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if string(params["verify"]) != "now" {
		t.Errorf("Expected verify parameter 'now', got '%s'", string(params["verify"]))
	}
}

// (AI GENERATED DESCRIPTION): Tests that `ChallengeDns.Request` returns an error when invoked with an unknown status value.
func TestChallengeDns_UnknownStatus(t *testing.T) {
	challenge := &ndncert.ChallengeDns{
		DomainCallback: func(status string) string {
			return "example.com"
		},
		ConfirmationCallback: func(recordName, expectedValue, status string) string {
			return "ready"
		},
	}

	input := ndncert.ParamMap{}
	status := optional.Some("unknown-status")
	_, err := challenge.Request(input, status)
	if err == nil {
		t.Error("Expected error for unknown status, got none")
	}
}

// (AI GENERATED DESCRIPTION): Tests that `ChallengeDns.Request` returns an error when the domain or confirmation callbacks are not configured.
func TestChallengeDns_NotConfigured(t *testing.T) {
	// Test with missing domain callback
	challenge := &ndncert.ChallengeDns{
		ConfirmationCallback: func(recordName, expectedValue, status string) string {
			return "ready"
		},
	}

	_, err := challenge.Request(nil, optional.Optional[string]{})
	if err == nil {
		t.Error("Expected error for missing domain callback, got none")
	}

	// Test with missing confirmation callback
	challenge2 := &ndncert.ChallengeDns{
		DomainCallback: func(status string) string {
			return "example.com"
		},
	}

	_, err = challenge2.Request(nil, optional.Optional[string]{})
	if err == nil {
		t.Error("Expected error for missing confirmation callback, got none")
	}
}

// Test domain validation helper functions (if we need to expose them for testing)
func TestIsValidDomainName(t *testing.T) {
	// Note: This test assumes isValidDomainName is exported
	// If not exported, we can test through the challenge Request method
	testCases := []struct {
		domain string
		valid  bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"test-domain.example.org", true},
		{"a.b", true},
		{"", false},
		{"-example.com", false},
		{"example-.com", false},
		{"example..com", false},
		{".example.com", false},
		{"example.com.", false},
	}

	for _, tc := range testCases {
		challenge := &ndncert.ChallengeDns{
			DomainCallback: func(status string) string {
				return tc.domain
			},
			ConfirmationCallback: func(recordName, expectedValue, status string) string {
				return "ready"
			},
		}

		_, err := challenge.Request(nil, optional.Optional[string]{})

		if tc.valid && err != nil {
			t.Errorf("Expected domain '%s' to be valid, got error: %v", tc.domain, err)
		}
		if !tc.valid && err == nil {
			t.Errorf("Expected domain '%s' to be invalid, got no error", tc.domain)
		}
	}
}
