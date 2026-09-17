package merklelog

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	defn "github.com/named-data/ndnd/std/ndn/merklelog"
)

var (
	appendKeyword = enc.NewKeywordComponent("append")
	checkKeyword  = enc.NewKeywordComponent("check")
)

// AppendPrefix returns the append command prefix under logPrefix.
func AppendPrefix(logPrefix enc.Name) enc.Name {
	return logPrefix.Clone().Append(appendKeyword)
}

// CheckPrefix returns the check object prefix under logPrefix.
func CheckPrefix(logPrefix enc.Name) enc.Name {
	return logPrefix.Clone().Append(checkKeyword)
}

// Client appends to and queries a Merkle history log. The supplied Object
// client must use a TrustConfig that signs append requests and strictly
// validates log response signatures.
type Client struct {
	client     ndn.Client
	appendName enc.Name
	checkName  enc.Name
	requester  enc.Name
	now        func() time.Time
}

// NewClient creates a client for logPrefix. requester identifies the request
// signer in command Data names.
func NewClient(client ndn.Client, logPrefix enc.Name, requester enc.Name) (*Client, error) {
	if client == nil {
		return nil, fmt.Errorf("Object client is nil")
	}
	if len(logPrefix) == 0 {
		return nil, fmt.Errorf("log prefix is empty")
	}
	if len(requester) == 0 {
		return nil, fmt.Errorf("requester name is empty")
	}
	return &Client{
		client:     client,
		appendName: AppendPrefix(logPrefix),
		checkName:  CheckPrefix(logPrefix),
		requester:  requester.Clone(),
		now:        time.Now,
	}, nil
}

// Append submits Data packet hashes to the log.
func (c *Client) Append(dataHashes [][]byte, callback func(*defn.AppendResponse, error)) {
	hashes, err := copyRequestHashes(dataHashes)
	if err != nil {
		callback(nil, err)
		return
	}
	requestName, err := c.requestName(c.appendName)
	if err != nil {
		callback(nil, err)
		return
	}
	c.client.ExpressCommand(
		c.appendName,
		requestName,
		(&defn.AppendRequest{DataHashes: hashes}).Encode(),
		func(wire enc.Wire, err error) {
			if err != nil {
				callback(nil, err)
				return
			}
			response, err := defn.ParseAppendResponse(enc.NewWireView(wire), false)
			if err != nil {
				callback(nil, fmt.Errorf("parse append response: %w", err))
				return
			}
			if err := validateAppendResponse(hashes, response); err != nil {
				callback(nil, err)
				return
			}
			callback(response, nil)
		},
	)
}

// Check retrieves and verifies the inclusion proof for one Data packet hash.
func (c *Client) Check(dataHash []byte, callback func(*defn.CheckResponse, error)) {
	if len(dataHash) != HashSize {
		callback(nil, fmt.Errorf("Data hash length is %d, want %d", len(dataHash), HashSize))
		return
	}
	hash := bytes.Clone(dataHash)
	name := c.checkName.Clone().Append(enc.NewGenericBytesComponent(hash))
	c.client.ConsumeExt(ndn.ConsumeExtArgs{
		Name:       name,
		NoMetadata: true,
		Callback: func(state ndn.ConsumeState) {
			if err := state.Error(); err != nil {
				callback(nil, fmt.Errorf("consume check response: %w", err))
				return
			}
			response, err := defn.ParseCheckResponse(enc.NewWireView(state.Content()), false)
			if err != nil {
				callback(nil, fmt.Errorf("parse check response: %w", err))
				return
			}
			if response.Root != nil && response.Root.TreeSize != state.Version() {
				callback(nil, fmt.Errorf(
					"check response tree size %d does not match object version %d",
					response.Root.TreeSize,
					state.Version(),
				))
				return
			}
			if err := validateCheckResponse(hash, response); err != nil {
				callback(nil, err)
				return
			}
			callback(response, nil)
		},
	})
}

func (c *Client) requestName(commandPrefix enc.Name) (enc.Name, error) {
	timestamp := c.now().UnixMilli()
	if timestamp < 0 {
		return nil, fmt.Errorf("request time is before the Unix epoch")
	}
	return commandPrefix.Clone().
		Append(c.requester...).
		Append(enc.NewTimestampComponent(uint64(timestamp))), nil
}

func copyRequestHashes(dataHashes [][]byte) ([][]byte, error) {
	if len(dataHashes) == 0 {
		return nil, fmt.Errorf("request has no Data hashes")
	}
	ret := make([][]byte, len(dataHashes))
	for i, dataHash := range dataHashes {
		if len(dataHash) != HashSize {
			return nil, fmt.Errorf("Data hash %d length is %d, want %d", i, len(dataHash), HashSize)
		}
		ret[i] = bytes.Clone(dataHash)
	}
	return ret, nil
}

func validateAppendResponse(dataHashes [][]byte, response *defn.AppendResponse) error {
	if response == nil {
		return fmt.Errorf("append response is nil")
	}
	if len(response.Results) != len(dataHashes) {
		return fmt.Errorf("append response has %d results, want %d", len(response.Results), len(dataHashes))
	}
	for i, result := range response.Results {
		if result == nil || !bytes.Equal(result.DataHash, dataHashes[i]) {
			return fmt.Errorf("append result %d does not match requested Data hash", i)
		}
		hasLeafIndex := result.LeafIndex.IsSet()
		switch result.Status {
		case defn.AppendStatusOK, defn.AppendStatusDuplicate:
			if !hasLeafIndex {
				return fmt.Errorf("append result %d has no leaf index", i)
			}
		case defn.AppendStatusFailed:
			if hasLeafIndex {
				return fmt.Errorf("failed append result %d has a leaf index", i)
			}
		default:
			return fmt.Errorf("append result %d has unknown status %d", i, result.Status)
		}
	}
	return nil
}

func validateCheckResponse(dataHash []byte, response *defn.CheckResponse) error {
	if response == nil || response.Root == nil {
		return fmt.Errorf("check response has no tree root")
	}
	if len(response.Root.RootHash) != HashSize {
		return fmt.Errorf("root hash length is %d, want %d", len(response.Root.RootHash), HashSize)
	}
	if response.Root.TreeSize == 0 {
		emptyRoot := sha256.Sum256(nil)
		if !bytes.Equal(response.Root.RootHash, emptyRoot[:]) {
			return fmt.Errorf("empty tree has an invalid root hash")
		}
	}
	result := response.Result
	if result == nil || !bytes.Equal(result.DataHash, dataHash) {
		return fmt.Errorf("check result does not match requested Data hash")
	}
	switch result.Status {
	case defn.CheckStatusIncluded:
		if err := VerifyInclusion(dataHash, result.Proof, response.Root); err != nil {
			return fmt.Errorf("check result has invalid inclusion proof: %w", err)
		}
	case defn.CheckStatusNotFound:
		if result.Proof != nil {
			return fmt.Errorf("not-found check result has an inclusion proof")
		}
	default:
		return fmt.Errorf("check result has unknown status %d", result.Status)
	}
	return nil
}
