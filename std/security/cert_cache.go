package security

import (
	"sync"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

// CertCache is a memcache for certificates.
// It stores certificates by their name and key locator.
// Only the most recent certificate is stored.
// The cache is thread-safe.
type CertCache struct {
	cache sync.Map
}

type certCacheEntry struct {
	data       ndn.Data
	sigCovered enc.Wire
	expiry     time.Time
}

// CertListCache stores validated CertList Data packets keyed by prefix and full name.
type CertListCache struct {
	cache sync.Map
}

// NewCertListCache creates a new CertListCache.
func NewCertListCache() *CertListCache {
	return &CertListCache{}
}

// Get returns a cached CertList for the given prefix or full name.
func (clc *CertListCache) Get(prefix enc.Name) (ndn.Data, bool) {
	if v, ok := clc.cache.Load(prefix.TlvStr()); ok {
		if data, ok := v.(ndn.Data); ok {
			return data, true
		}
	}
	return nil, false
}

// Put stores a CertList, preferring newer versions.
func (clc *CertListCache) Put(anchorKeyName enc.Name, data ndn.Data) {
	prefix, err := CertListPrefix(anchorKeyName)
	if err != nil {
		return
	}
	key := prefix.TlvStr()
	if v, ok := clc.cache.Load(key); ok {
		if old, ok := v.(ndn.Data); ok && !isCertListNewer(old, data) {
			return
		}
	}
	clc.cache.Store(key, data)
	clc.cache.Store(data.Name().TlvStr(), data)
}

func isCertListNewer(old, new ndn.Data) bool {
	return CertListVersion(new.Name()) > CertListVersion(old.Name())
}

// (AI GENERATED DESCRIPTION): Creates and returns a new, empty CertCache instance.
func NewCertCache() *CertCache {
	return &CertCache{}
}

// Get retrieves a certificate from the cache.
// The name can be either the certificate name or the key locator.
// Entries are retained until five minutes after certificate expiry.
func (cc *CertCache) Get(name enc.Name) (ndn.Data, bool) {
	entry, ok := cc.get(name)
	return entry.data, ok
}

// get retrieves the certificate and its signature verification evidence.
func (cc *CertCache) get(name enc.Name) (certCacheEntry, bool) {
	str := name.TlvStr()
	if v, ok := cc.cache.Load(str); ok {
		entry := v.(certCacheEntry)
		if entry.expiry.Add(5 * time.Minute).After(time.Now()) {
			return entry, true
		} else {
			cc.cache.Delete(str)
		}
	}
	return certCacheEntry{}, false
}

// Put stores certificate data without signature verification evidence.
func (cc *CertCache) Put(cert ndn.Data) {
	cc.put(cert, nil)
}

// put stores a certificate with the wire covered by its signature.
func (cc *CertCache) put(cert ndn.Data, sigCovered enc.Wire) {
	_, expiry := cert.Signature().Validity()
	if !expiry.IsSet() {
		return // huh?
	}

	entry := certCacheEntry{
		data:       cert,
		sigCovered: sigCovered,
		expiry:     expiry.Unwrap(),
	}

	// Store the certificate by its own name
	cc.cache.Store(cert.Name().TlvStr(), entry)

	// Store the certificate by the key locator w/ issuer
	cc.cache.Store(cert.Name().Prefix(-1).TlvStr(), entry)

	// Store the certificate by the key locator w/o issuer
	cc.cache.Store(cert.Name().Prefix(-2).TlvStr(), entry)
}
