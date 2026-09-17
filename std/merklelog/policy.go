package merklelog

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/named-data/ndnd/std/ndn"
	defn "github.com/named-data/ndnd/std/ndn/merklelog"
)

// NewCertExpiredPolicy creates an expiry policy backed by a Merkle history
// log. The log client's Object client must strictly validate log responses;
// log response validation must not use this policy recursively.
func NewCertExpiredPolicy(client *Client) ndn.CertExpiredCallback {
	return func(args ndn.CertExpiredCallbackArgs, complete func(error)) {
		if client == nil {
			complete(fmt.Errorf("Merkle log client is nil"))
			return
		}
		if args.Data == nil {
			complete(fmt.Errorf("Data packet is nil"))
			return
		}
		if args.RawData.Length() == 0 {
			complete(fmt.Errorf("Data packet wire is unavailable: %s", args.Data.Name()))
			return
		}
		if args.Cert == nil || args.Cert.Signature() == nil {
			complete(fmt.Errorf("certificate is missing or unsigned"))
			return
		}

		notBefore, notAfter := args.Cert.Signature().Validity()
		validFrom, hasValidFrom := notBefore.Get()
		validUntil, hasValidUntil := notAfter.Get()
		if !hasValidFrom || !hasValidUntil || validUntil.Before(validFrom) {
			complete(fmt.Errorf("certificate has an invalid validity period: %s", args.Cert.Name()))
			return
		}

		dataHash := sha256.Sum256(args.RawData.Join())
		client.Check(dataHash[:], func(response *defn.CheckResponse, err error) {
			if err != nil {
				complete(fmt.Errorf("Merkle log check failed: %w", err))
				return
			}
			// Check has verified the response shape, requested hash, and proof.
			result := response.Result
			if result.Status != defn.CheckStatusIncluded {
				complete(fmt.Errorf("Data packet is not present in the Merkle log: %s", args.Data.Name()))
				return
			}

			// Parse the verified entry to apply the policy to its ingestion time.
			entry, err := ParseProofEntry(result.Proof)
			if err != nil {
				complete(fmt.Errorf("parse proven log entry: %w", err))
				return
			}
			ingestTime := time.Unix(0, int64(entry.IngestTime))
			if ingestTime.Before(validFrom) || ingestTime.After(validUntil) {
				complete(fmt.Errorf(
					"Data packet was logged outside certificate validity: %s",
					args.Data.Name(),
				))
				return
			}
			complete(nil)
		})
	}
}
