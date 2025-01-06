package engine

import (
	"fmt"
	"net/url"
	"os"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/engine/face"
	"github.com/named-data/ndnd/std/ndn"
	sec "github.com/named-data/ndnd/std/security"
)

// TODO: this API will change once there is a real security model
func NewBasicEngine(face face.Face) ndn.Engine {
	timer := basic.NewTimer()
	cmdSigner := sec.NewSha256IntSigner(timer)
	cmdValidator := func(enc.Name, enc.Wire, ndn.Signature) bool {
		return true
	}
	return basic.NewEngine(face, timer, cmdSigner, cmdValidator)
}

func NewUnixFace(addr string) face.Face {
	return face.NewStreamFace("unix", addr, true)
}

func NewDefaultFace() face.Face {
	config := GetClientConfig()

	// Parse transport URI
	uri, err := url.Parse(config.TransportUri)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse transport URI %s: %v (invalid client config)\n", uri, err)
		os.Exit(1)
	}

	if uri.Scheme == "unix" {
		return NewUnixFace(uri.Path)
	}

	if uri.Scheme == "tcp" || uri.Scheme == "tcp4" || uri.Scheme == "tcp6" {
		return face.NewStreamFace(uri.Scheme, uri.Host, false)
	}

	fmt.Fprintf(os.Stderr, "Unsupported transport URI: %s (invalid client config)\n", uri)
	os.Exit(1)

	return nil
}
