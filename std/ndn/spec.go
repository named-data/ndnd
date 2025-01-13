package ndn

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
)

// Spec represents an NDN packet specification.
type Spec interface {
	// MakeData creates a Data packet, returns the encoded DataContainer
	MakeData(name enc.Name, config *DataConfig, content enc.Wire, signer Signer) (*EncodedData, error)
	// MakeData creates an Interest packet, returns an encoded InterestContainer
	MakeInterest(name enc.Name, config *InterestConfig, appParam enc.Wire, signer Signer) (*EncodedInterest, error)
	// ReadData reads and parses a Data from the reader, returns the Data, signature covered parts, and error.
	ReadData(reader enc.ParseReader) (Data, enc.Wire, error)
	// ReadData reads and parses an Interest from the reader, returns the Data, signature covered parts, and error.
	ReadInterest(reader enc.ParseReader) (Interest, enc.Wire, error)
}

// Interest is the abstract of a received Interest packet
type Interest interface {
	// Name of the Interest packet
	Name() enc.Name
	// Indicates whether a Data with a longer name can match
	CanBePrefix() bool
	// Indicates whether the Data must be fresh
	MustBeFresh() bool
	// ForwardingHint is the list of names to guide the Interest forwarding
	ForwardingHint() []enc.Name
	// Number to identify the Interest uniquely
	Nonce() *uint64
	// Lifetime of the Interest
	Lifetime() *time.Duration
	// Max number of hops the Interest can traverse
	HopLimit() *byte
	// Application parameters of the Interest (optional)
	AppParam() enc.Wire
	// Signature on the Interest (optional)
	Signature() Signature
}

// InterestConfig is used to create a Interest.
type InterestConfig struct {
	CanBePrefix    bool
	MustBeFresh    bool
	ForwardingHint []enc.Name
	Nonce          *uint64
	Lifetime       *time.Duration
	HopLimit       *uint
}

// Container for an encoded Interest packet
type EncodedInterest struct {
	// Encoded Interest packet
	Wire enc.Wire
	// Signed part of the Interest
	SigCovered enc.Wire
	// Final name of the Interest
	FinalName enc.Name
	// Parameter configuration of the Interest
	Config *InterestConfig
}

// Data is the abstract of a received Data packet.
type Data interface {
	Name() enc.Name
	ContentType() *ContentType
	Freshness() *time.Duration
	FinalBlockID() *enc.Component
	Content() enc.Wire

	Signature() Signature
}

// DataConfig is used to create a Data.
type DataConfig struct {
	ContentType  *ContentType
	Freshness    *time.Duration
	FinalBlockID *enc.Component
}

// Container for an encoded Data packet
type EncodedData struct {
	// Encoded Data packet
	Wire enc.Wire
	// Signed part of the Data
	SigCovered enc.Wire
	// Parameter configuration of the Data
	Config *DataConfig
}
