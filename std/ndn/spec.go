package ndn

import (
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/types/optional"
)

// Spec represents an NDN packet specification.
type Spec interface {
	// MakeData creates a Data packet, returns the encoded DataContainer
	MakeData(name enc.Name, config *DataConfig, content enc.Wire, signer Signer) (*EncodedData, error)
	// MakeData creates an Interest packet, returns an encoded InterestContainer
	MakeInterest(name enc.Name, config *InterestConfig, appParam enc.Wire, signer Signer) (*EncodedInterest, error)
	// ReadData reads and parses a Data from the reader, returns the Data, signature covered parts, and error.
	ReadData(reader enc.WireView) (Data, enc.Wire, error)
	// ReadData reads and parses an Interest from the reader, returns the Data, signature covered parts, and error.
	ReadInterest(reader enc.WireView) (Interest, enc.Wire, error)
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
	Nonce() optional.Optional[uint32]
	// Lifetime of the Interest
	Lifetime() optional.Optional[time.Duration]
	// Max number of hops the Interest can traverse
	HopLimit() *uint
	// Application parameters of the Interest (optional)
	AppParam() enc.Wire
	// Signature on the Interest (optional)
	Signature() Signature
}

// InterestConfig is used to create a Interest.
type InterestConfig struct {
	// Standard Interest parameters
	CanBePrefix    bool
	MustBeFresh    bool
	ForwardingHint []enc.Name
	Nonce          optional.Optional[uint32]
	Lifetime       optional.Optional[time.Duration]
	HopLimit       *byte

	// Signed Interest parameters.
	// The use of signed interests is strongly discouraged, and will
	// be gradually phased out, which is why these parameters are
	// not directly provided by the signer.
	SigNonce []byte
	SigTime  optional.Optional[time.Duration]
	SigSeqNo optional.Optional[uint64]

	// NDNLPv2 parameters
	NextHopId optional.Optional[uint64]
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
	ContentType() optional.Optional[ContentType]
	Freshness() optional.Optional[time.Duration]
	FinalBlockID() optional.Optional[enc.Component]
	Content() enc.Wire
	Signature() Signature
	CrossSchema() enc.Wire
}

// DataConfig is used to create a Data.
type DataConfig struct {
	// Standard Data parameters
	ContentType  optional.Optional[ContentType]
	Freshness    optional.Optional[time.Duration]
	FinalBlockID optional.Optional[enc.Component]

	// Certificate parameters
	SigNotBefore optional.Optional[time.Time]
	SigNotAfter  optional.Optional[time.Time]

	// Cross Schema attachment
	CrossSchema enc.Wire
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
