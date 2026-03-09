package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/named-data/ndnd/std/security/ndncert"
)

// server-side DNS-01 challenge. requester proves domain ownership by putting a TXT record we can look up
type ChallengeDnsHandler struct {
	// override for testing, nil = net.LookupTXT
	DNSResolver func(domain string) ([]string, error)
}

func (h *ChallengeDnsHandler) HandleChallenge(params ndncert.ParamMap, state *RequestState) (ndncert.ParamMap, string, error) {
	if state.Status == StatusBeforeChallenge {
		domain, ok := params[ndncert.KwDomain]
		if !ok || len(domain) == 0 {
			return nil, "", fmt.Errorf("missing domain")
		}

		token := make([]byte, 32)
		if _, err := rand.Read(token); err != nil {
			return nil, "", err
		}
		tokenB64 := base64.StdEncoding.EncodeToString(token)

		state.SetChallengeStateValue("domain", domain)
		state.SetChallengeStateValue("token", token)
		state.Status = StatusChallenge

		rec := fmt.Sprintf("%s.%s", ndncert.DNSPrefix, string(domain))
		return ndncert.ParamMap{
			ndncert.KwRecordName:    []byte(rec),
			ndncert.KwExpectedValue: []byte(tokenB64),
		}, "need-record", nil
	}

	if state.Status == StatusChallenge {
		conf, ok := params[ndncert.KwConfirmation]
		if !ok || string(conf) != "ready" {
			return nil, "", fmt.Errorf("expected confirmation=ready")
		}

		domainBytes, _ := state.GetChallengeStateValue("domain")
		tokenBytes, _ := state.GetChallengeStateValue("token")
		if domainBytes == nil || tokenBytes == nil {
			return nil, "", fmt.Errorf("challenge state missing")
		}
		domain := string(domainBytes)
		expected := base64.StdEncoding.EncodeToString(tokenBytes)

		rec := fmt.Sprintf("%s.%s", ndncert.DNSPrefix, domain)
		records, err := h.lookupTXT(rec)

		// build retry response in case we need it
		retry := ndncert.ParamMap{
			ndncert.KwRecordName:    []byte(rec),
			ndncert.KwExpectedValue: []byte(expected),
		}

		if err != nil {
			return retry, "wrong-record", nil
		}

		for _, r := range records {
			if strings.TrimSpace(strings.Trim(r, "\"")) == expected {
				state.Status = StatusSuccess
				return nil, "", nil
			}
		}

		return retry, "wrong-record", nil
	}

	return nil, "", fmt.Errorf("unexpected status %d", state.Status)
}

func (h *ChallengeDnsHandler) lookupTXT(name string) ([]string, error) {
	if h.DNSResolver != nil {
		return h.DNSResolver(name)
	}
	return net.LookupTXT(name)
}
