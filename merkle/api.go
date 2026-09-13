package merkle

import (
	"bytes"
	"fmt"
	"math"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/merklelog"
	defn "github.com/named-data/ndnd/std/ndn/merklelog"
	"github.com/named-data/ndnd/std/types/optional"
)

const requestFreshnessWindow = time.Minute

func (m *Log) onAppend(name enc.Name, content enc.Wire, reply func(enc.Wire) error) {
	if err := m.validateRequestName(name, merklelog.AppendPrefix(m.config.nameN)); err != nil {
		log.Debug(m, "Rejected append request", "err", err)
		return
	}
	request, err := defn.ParseAppendRequest(enc.NewWireView(content), false)
	if err != nil {
		log.Debug(m, "Failed to parse append request", "err", err)
		return
	}
	go func() {
		response, appendErr := m.append(request)
		if appendErr != nil {
			log.Error(m, "Failed to append Data hashes", "err", appendErr)
		}
		if response != nil {
			if err := reply(response.Encode()); err != nil {
				log.Warn(m, "Failed to reply to append request", "err", err)
			}
		}
	}()
}

func (m *Log) onCheck(name enc.Name, content enc.Wire, reply func(enc.Wire) error) {
	if err := m.validateRequestName(name, merklelog.CheckPrefix(m.config.nameN)); err != nil {
		log.Debug(m, "Rejected check request", "err", err)
		return
	}
	request, err := defn.ParseCheckRequest(enc.NewWireView(content), false)
	if err != nil {
		log.Debug(m, "Failed to parse check request", "err", err)
		return
	}
	go func() {
		response, err := m.check(request)
		if err != nil {
			log.Debug(m, "Rejected check request", "err", err)
			return
		}
		if err := reply(response.Encode()); err != nil {
			log.Warn(m, "Failed to reply to check request", "err", err)
		}
	}()
}

func (m *Log) append(request *defn.AppendRequest) (*defn.AppendResponse, error) {
	if request == nil || len(request.DataHashes) == 0 {
		return nil, fmt.Errorf("append request has no Data hashes")
	}

	m.treeMutex.Lock()
	defer m.treeMutex.Unlock()
	if m.tree == nil {
		return nil, fmt.Errorf("Merkle tree is not available")
	}

	response := &defn.AppendResponse{Results: make([]*defn.AppendResult, len(request.DataHashes))}
	pending := make(map[[merklelog.HashSize]byte][]int)
	newHashes := make([][]byte, 0, len(request.DataHashes))
	for i, dataHash := range request.DataHashes {
		result := &defn.AppendResult{
			DataHash: bytes.Clone(dataHash),
			Status:   defn.AppendStatusFailed,
		}
		response.Results[i] = result
		if len(dataHash) != merklelog.HashSize {
			continue
		}
		if leafIndex, ok := m.tree.Lookup(dataHash); ok {
			result.Status = defn.AppendStatusDuplicate
			result.LeafIndex = optional.Some(leafIndex)
			continue
		}

		var key [merklelog.HashSize]byte
		copy(key[:], dataHash)
		if indexes, ok := pending[key]; ok {
			result.Status = defn.AppendStatusDuplicate
			pending[key] = append(indexes, i)
			continue
		}
		result.Status = defn.AppendStatusOK
		pending[key] = []int{i}
		newHashes = append(newHashes, bytes.Clone(dataHash))
	}
	if len(newHashes) == 0 {
		return response, nil
	}

	entryWire, err := merklelog.EncodeLogEntry(&defn.LogEntry{
		IngestTime: m.nextIngestTime(),
		DataHashes: newHashes,
	})
	if err != nil {
		markAppendFailed(response, pending)
		return response, err
	}
	leafIndex, err := m.tree.Append(entryWire)
	if err != nil {
		markAppendFailed(response, pending)
		return response, err
	}
	for _, indexes := range pending {
		for _, i := range indexes {
			response.Results[i].LeafIndex = optional.Some(leafIndex)
		}
	}
	return response, nil
}

func (m *Log) check(request *defn.CheckRequest) (*defn.CheckResponse, error) {
	if request == nil || len(request.DataHashes) == 0 {
		return nil, fmt.Errorf("check request has no Data hashes")
	}
	for i, dataHash := range request.DataHashes {
		if len(dataHash) != merklelog.HashSize {
			return nil, fmt.Errorf(
				"Data hash %d length is %d, want %d",
				i,
				len(dataHash),
				merklelog.HashSize,
			)
		}
	}

	m.treeMutex.Lock()
	defer m.treeMutex.Unlock()
	if m.tree == nil {
		return nil, fmt.Errorf("Merkle tree is not available")
	}

	response := &defn.CheckResponse{
		Root:    m.tree.Root(),
		Results: make([]*defn.CheckResult, len(request.DataHashes)),
	}
	for i, dataHash := range request.DataHashes {
		result := &defn.CheckResult{
			DataHash: bytes.Clone(dataHash),
			Status:   defn.CheckStatusNotFound,
		}
		response.Results[i] = result
		if leafIndex, ok := m.tree.Lookup(dataHash); ok {
			proof, err := m.tree.InclusionProof(leafIndex)
			if err != nil {
				return nil, err
			}
			result.Status = defn.CheckStatusIncluded
			result.Proof = proof
		}
	}
	return response, nil
}

func (m *Log) validateRequestName(name enc.Name, commandPrefix enc.Name) error {
	if !commandPrefix.IsPrefix(name) || len(name) < len(commandPrefix)+2 {
		return fmt.Errorf("request name does not match %s/<requester>/t=<timestamp>", commandPrefix)
	}
	timestamp := name.At(-1)
	if !timestamp.IsTimestamp() {
		return fmt.Errorf("request name has no timestamp component")
	}
	timestampValue := timestamp.NumberVal()
	if len(timestamp.Val) != enc.Nat(timestampValue).EncodingLength() || timestampValue > math.MaxInt64 {
		return fmt.Errorf("request timestamp is not canonical")
	}
	requestTime := time.UnixMilli(int64(timestampValue))
	now := m.now()
	if requestTime.Before(now.Add(-requestFreshnessWindow)) ||
		requestTime.After(now.Add(requestFreshnessWindow)) {
		return fmt.Errorf("request timestamp is outside the permitted window")
	}
	return nil
}

func (m *Log) nextIngestTime() time.Duration {
	next := time.Duration(m.now().UnixMilli()) * time.Millisecond
	if last, ok := m.tree.LastIngestTime(); ok && next <= last {
		return last + time.Millisecond
	}
	return next
}

func markAppendFailed(response *defn.AppendResponse, pending map[[merklelog.HashSize]byte][]int) {
	for _, indexes := range pending {
		for _, i := range indexes {
			response.Results[i].Status = defn.AppendStatusFailed
			response.Results[i].LeafIndex.Unset()
		}
	}
}
