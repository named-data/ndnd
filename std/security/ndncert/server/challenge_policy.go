package server

import (
	"fmt"
	"strings"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/ndncert"
	"github.com/named-data/ndnd/std/security/signer"
)

func (ca *CaServer) validateChallengeSignature(args ndn.InterestHandlerArgs, state *RequestState) error {
	cert, _, err := ca.engine.Spec().ReadData(enc.NewWireView(state.CertRequest))
	if err != nil {
		return fmt.Errorf("invalid stored certificate request")
	}
	keyName, err := security.GetKeyNameFromCertName(cert.Name())
	if err != nil || args.Interest.Signature() == nil || !args.Interest.Signature().KeyName().Equal(keyName) {
		return fmt.Errorf("CHALLENGE Interest key locator does not match certificate request")
	}
	valid, err := signer.ValidateInterest(args.Interest, args.SigCovered, cert)
	if err != nil || !valid {
		return fmt.Errorf("CHALLENGE Interest signature is invalid")
	}
	return nil
}

// PROBE is optional and only suggests names. Authorization is enforced when
// the requester selects the challenge, before sending mail or querying DNS.
func (ca *CaServer) validateChallengeIdentity(challenge string, params ndncert.ParamMap, state *RequestState) error {
	identity, err := security.GetIdentityFromCertName(state.RequestedCertName)
	if err != nil {
		return fmt.Errorf("invalid requested identity")
	}
	var authorized enc.Name
	switch challenge {
	case ndncert.KwEmail:
		format, ok := ca.config.NameAssignment[ndncert.KwEmail]
		if !ok {
			return fmt.Errorf("email name-assignment is not configured")
		}
		suffix, ok := assignEmailName(format, params[ndncert.KwEmail])
		if !ok {
			return fmt.Errorf("invalid email name assignment")
		}
		authorized = ca.caPrefix.Clone().Append(suffix...)
	case ndncert.KwDns:
		domain := string(params[ndncert.KwDomain])
		if !validDNSIdentityDomain(domain) {
			return fmt.Errorf("DNS domain must be a canonical lowercase hostname")
		}
		// Match certcli's DNS identity convention exactly. Domain ownership
		// does not authorize unrelated identities or arbitrary descendants.
		authorized = ca.caPrefix.Clone().Append(enc.NewGenericComponent(domain))
	default:
		return fmt.Errorf("unsupported challenge identity policy")
	}
	if !identity.Equal(authorized) {
		return fmt.Errorf("requested identity is not authorized by this challenge")
	}
	return nil
}

func validDNSIdentityDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
