// Package merkle implements the Merkle history log daemon.
package merkle

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/merklelog"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/security/keychain"
)

const (
	packetStoreDir = "packets"
	logStoreDir    = "log"
)

// Log is a Merkle history log service.
type Log struct {
	config *Config

	engine ndn.Engine
	client ndn.Client

	packetStore *storage.BadgerStore
	logStore    *merklelog.BadgerStore
	tree        *merklelog.Tree

	keychain ndn.KeyChain
	trust    *sec.TrustConfig

	treeMutex sync.Mutex
	now       func() time.Time

	clientStarted         bool
	appendHandlerAttached bool
	checkHandlerAttached  bool
	started               bool
}

// NewLog creates a stopped Merkle history log service.
func NewLog(config *Config) *Log {
	return &Log{
		config: config,
		now:    time.Now,
	}
}

// String returns the service's log identifier.
func (*Log) String() string {
	return "merkle-log"
}

// Start opens persistent state and starts the network-facing service.
func (m *Log) Start() (err error) {
	if m.started || m.packetStore != nil || m.logStore != nil || m.engine != nil || m.client != nil {
		return fmt.Errorf("merkle log is already started")
	}
	if m.config == nil {
		return fmt.Errorf("merkle log configuration is nil")
	}
	if err := m.config.Parse(); err != nil {
		return err
	}

	log.Info(m, "Starting Merkle history log", "dir", m.config.StorageDir)
	defer func() {
		if err != nil {
			err = errors.Join(err, m.stop())
		}
	}()

	m.packetStore, err = storage.NewBadgerStore(filepath.Join(m.config.StorageDir, packetStoreDir))
	if err != nil {
		return fmt.Errorf("open packet store: %w", err)
	}
	m.logStore, err = merklelog.NewBadgerStore(filepath.Join(m.config.StorageDir, logStoreDir))
	if err != nil {
		return fmt.Errorf("open Merkle log store: %w", err)
	}
	m.tree, err = merklelog.OpenTree(m.logStore)
	if err != nil {
		return fmt.Errorf("restore Merkle tree: %w", err)
	}

	m.keychain, err = keychain.NewKeyChain(m.config.KeyChainUri, m.packetStore)
	if err != nil {
		return fmt.Errorf("open keychain: %w", err)
	}
	m.trust, err = sec.NewTrustConfig(
		m.keychain,
		m.config.trustSchema,
		m.config.trustAnchors,
	)
	if err != nil {
		return fmt.Errorf("create trust configuration: %w", err)
	}
	m.trust.UseDataNameFwHint = true

	m.engine = engine.NewBasicEngine(engine.NewDefaultFace())
	if err = m.engine.Start(); err != nil {
		return fmt.Errorf("start NDN engine: %w", err)
	}

	m.client = object.NewClient(m.engine, m.packetStore, m.trust)
	if err = m.client.Start(); err != nil {
		return fmt.Errorf("start Object client: %w", err)
	}
	m.clientStarted = true
	if err = m.client.AttachCommandHandler(merklelog.AppendPrefix(m.config.nameN), m.onAppend); err != nil {
		return fmt.Errorf("attach append handler: %w", err)
	}
	m.appendHandlerAttached = true
	if err = m.engine.AttachHandler(merklelog.CheckPrefix(m.config.nameN), m.onCheck); err != nil {
		return fmt.Errorf("attach check handler: %w", err)
	}
	m.checkHandlerAttached = true
	m.client.AnnouncePrefix(ndn.Announcement{
		Name:   m.config.nameN,
		Expose: true,
	})
	m.started = true
	return nil
}

// Stop stops the network service and closes its persistent stores.
func (m *Log) Stop() error {
	if m.started {
		log.Info(m, "Stopping Merkle history log")
	}
	return m.stop()
}

func (m *Log) stop() error {
	var errs []error
	if m.client != nil {
		if m.started {
			m.client.WithdrawPrefix(m.config.nameN, nil)
		}
		if m.checkHandlerAttached {
			if err := m.engine.DetachHandler(merklelog.CheckPrefix(m.config.nameN)); err != nil {
				errs = append(errs, fmt.Errorf("detach check handler: %w", err))
			}
			m.checkHandlerAttached = false
		}
		if m.appendHandlerAttached {
			if err := m.client.DetachCommandHandler(merklelog.AppendPrefix(m.config.nameN)); err != nil {
				errs = append(errs, fmt.Errorf("detach append handler: %w", err))
			}
			m.appendHandlerAttached = false
		}
		if m.clientStarted {
			if err := m.client.Stop(); err != nil {
				errs = append(errs, fmt.Errorf("stop Object client: %w", err))
			}
		}
		m.client = nil
		m.clientStarted = false
	}
	if m.engine != nil {
		if m.engine.IsRunning() {
			if err := m.engine.Stop(); err != nil {
				errs = append(errs, fmt.Errorf("stop NDN engine: %w", err))
			}
		}
		m.engine = nil
	}
	m.treeMutex.Lock()
	if m.logStore != nil {
		if err := m.logStore.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close Merkle log store: %w", err))
		}
		m.logStore = nil
	}
	m.tree = nil
	m.treeMutex.Unlock()
	if m.packetStore != nil {
		if err := m.packetStore.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close packet store: %w", err))
		}
		m.packetStore = nil
	}

	m.keychain = nil
	m.trust = nil
	m.started = false
	return errors.Join(errs...)
}
