package engine

import (
	"fmt"
	"net/url"
	"os"

	"github.com/named-data/ndnd/std/engine/basic"
	"github.com/named-data/ndnd/std/engine/face"
	"github.com/named-data/ndnd/std/ndn"
)

func NewBasicEngine(face ndn.Face) ndn.Engine {
	return basic.NewEngine(face, basic.NewTimer())
}

func NewUnixFace(addr string) ndn.Face {
	return face.NewStreamFace("unix", addr, true)
}

func NewDefaultFace() ndn.Face {
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
