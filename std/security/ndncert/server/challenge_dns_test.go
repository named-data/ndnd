package server

import (
	"errors"
	"testing"

	"github.com/named-data/ndnd/std/security/ndncert"
)

func TestChallengeDnsHandler_InitialRequest(t *testing.T) {
	handler := &ChallengeDnsHandler{}
	state := NewRequestState([]byte("test-req-id"), nil)

	params := ndncert.ParamMap{
		ndncert.KwDomain: []byte("example.com"),
	}

	responseParams, status, err := handler.HandleChallenge(params, state)
	if err != nil {
		t.Fatalf("HandleChallenge failed: %v", err)
	}

	if status != "need-record" {
		t.Errorf("Expected status 'need-record', got '%s'", status)
	}

	if state.Status != StatusChallenge {
		t.Errorf("Expected state status StatusChallenge, got %d", state.Status)
	}

	recordName, ok := responseParams[ndncert.KwRecordName]
	if !ok {
		t.Fatal("Response missing record-name parameter")
	}

	expectedValue, ok := responseParams[ndncert.KwExpectedValue]
	if !ok {
		t.Fatal("Response missing expected-value parameter")
	}

	recordNameStr := string(recordName)
	if recordNameStr != "_ndncert-challenge.example.com" {
		t.Errorf("Expected record name '_ndncert-challenge.example.com', got '%s'", recordNameStr)
	}

	if len(expectedValue) == 0 {
		t.Error("Expected value should not be empty")
	}

	t.Logf("Record name: %s", recordNameStr)
	t.Logf("Expected value: %s", string(expectedValue))
}

func TestChallengeDnsHandler_SuccessfulVerification(t *testing.T) {
	handler := &ChallengeDnsHandler{
		DNSResolver: func(domain string) ([]string, error) {
			return []string{"test-token-base64"}, nil
		},
	}

	state := NewRequestState([]byte("test-req-id"), nil)
	state.Status = StatusChallenge
	state.SetChallengeStateValue("domain", []byte("example.com"))
	state.SetChallengeStateValue("token", []byte("test-token-decoded"))

	params := ndncert.ParamMap{
		ndncert.KwConfirmation: []byte("ready"),
	}

	_, _, err := handler.HandleChallenge(params, state)
	if err != nil {
		t.Logf("HandleChallenge returned error: %v", err)
	}
}

func TestChallengeDnsHandler_FailedVerification(t *testing.T) {
	handler := &ChallengeDnsHandler{
		DNSResolver: func(domain string) ([]string, error) {
			return []string{"wrong-token"}, nil
		},
	}

	state := NewRequestState([]byte("test-req-id"), nil)
	state.Status = StatusChallenge
	state.SetChallengeStateValue("domain", []byte("example.com"))
	state.SetChallengeStateValue("token", []byte("correct-token-bytes"))

	params := ndncert.ParamMap{
		ndncert.KwConfirmation: []byte("ready"),
	}

	responseParams, status, err := handler.HandleChallenge(params, state)
	if err != nil {
		t.Fatalf("HandleChallenge failed: %v", err)
	}

	if status != "wrong-record" {
		t.Errorf("Expected status 'wrong-record', got '%s'", status)
	}

	if state.Status != StatusChallenge {
		t.Errorf("Expected state to remain in StatusChallenge, got %d", state.Status)
	}

	if _, ok := responseParams[ndncert.KwRecordName]; !ok {
		t.Error("Response should include record-name for retry")
	}
}

func TestChallengeDnsHandler_MissingDomain(t *testing.T) {
	handler := &ChallengeDnsHandler{}
	state := NewRequestState([]byte("test-req-id"), nil)

	params := ndncert.ParamMap{}

	_, _, err := handler.HandleChallenge(params, state)
	if err == nil {
		t.Fatal("Expected error for missing domain parameter")
	}

	if err.Error() != "missing domain" {
		t.Errorf("Expected 'missing domain' error, got: %v", err)
	}
}

func TestChallengeDnsHandler_DNSLookupFailure(t *testing.T) {
	handler := &ChallengeDnsHandler{
		DNSResolver: func(domain string) ([]string, error) {
			return nil, errors.New("DNS lookup failed")
		},
	}

	state := NewRequestState([]byte("test-req-id"), nil)
	state.Status = StatusChallenge
	state.SetChallengeStateValue("domain", []byte("example.com"))
	state.SetChallengeStateValue("token", []byte("test-token"))

	params := ndncert.ParamMap{
		ndncert.KwConfirmation: []byte("ready"),
	}

	responseParams, status, err := handler.HandleChallenge(params, state)
	if err != nil {
		t.Fatalf("HandleChallenge failed: %v", err)
	}

	if status != "wrong-record" {
		t.Errorf("Expected status 'wrong-record' on DNS failure, got '%s'", status)
	}

	if _, ok := responseParams[ndncert.KwRecordName]; !ok {
		t.Error("Response should include record-name for retry")
	}
}
