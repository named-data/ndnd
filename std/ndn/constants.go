package ndn

// MaxNDNPacketSize is the maximum allowed NDN packet size
const MaxNDNPacketSize = 8800

// ContentType represents the type of Data content in MetaInfo.
type ContentType uint64

const (
	ContentTypeBlob               ContentType = 0
	ContentTypeLink               ContentType = 1
	ContentTypeKey                ContentType = 2
	ContentTypeNack               ContentType = 3
	ContentTypeManifest           ContentType = 4
	ContentTypePrefixAnnouncement ContentType = 5
	ContentTypeEncapsulatedData   ContentType = 6
	ContentTypeSigningKey         ContentType = 9
)

// SigType represents the type of signature.
type SigType int

const (
	SignatureNone            SigType = -1
	SignatureDigestSha256    SigType = 0
	SignatureSha256WithRsa   SigType = 1
	SignatureSha256WithEcdsa SigType = 3
	SignatureHmacWithSha256  SigType = 4
	SignatureEd25519         SigType = 5
	SignatureEmptyTest       SigType = 200
)

// (AI GENERATED DESCRIPTION): Returns a human‑readable string that names the signature type represented by the SigType value, defaulting to “Unknown” if no match.
func (t SigType) String() string {
	switch t {
	case SignatureNone:
		return "None"
	case SignatureDigestSha256:
		return "DigestSha256"
	case SignatureSha256WithRsa:
		return "Sha256WithRsa"
	case SignatureSha256WithEcdsa:
		return "Sha256WithEcdsa"
	case SignatureHmacWithSha256:
		return "HmacWithSha256"
	case SignatureEd25519:
		return "Ed25519"
	case SignatureEmptyTest:
		return "EmptyTest"
	default:
		return "Unknown"
	}
}

// InterestResult represents the result of Interest expression.
// Can be Data fetched (succeeded), NetworkNack received, or Timeout.
// Note that AppNack is considered as Data.
type InterestResult int

const (
	// Empty result. Not used by the engine.
	// Used by high-level part if the setting to construct an Interest is incorrect.
	InterestResultNone InterestResult = iota
	// Data is fetched
	InterestResultData
	// NetworkNack is received
	InterestResultNack
	// Timeout
	InterestResultTimeout
	// Cancelled due to disconnection
	InterestCancelled
	// Failed of validation. Not used by the engine itself.
	InterestResultUnverified
	// Other error happens during handling the fetched data. Not used by the engine itself.
	InterestResultError
)

// (AI GENERATED DESCRIPTION): Returns the string name corresponding to the given InterestResult enum value.
func (r InterestResult) String() string {
	switch r {
	case InterestResultNone:
		return "None"
	case InterestResultData:
		return "Data"
	case InterestResultNack:
		return "Nack"
	case InterestResultTimeout:
		return "Timeout"
	case InterestCancelled:
		return "Cancelled"
	case InterestResultUnverified:
		return "Unverified"
	case InterestResultError:
		return "Error"
	default:
		return "Unknown"
	}
}
