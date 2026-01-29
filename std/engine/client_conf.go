package engine

import (
	"bufio"
	"os"
	"runtime"
	"strings"
)

type ClientConfig struct {
	TransportUri string
}

// (AI GENERATED DESCRIPTION): Retrieves the NDN client configuration, starting with a default transport URI and overriding it with values from `client.conf` files in prioritized directories and the `NDN_CLIENT_TRANSPORT` environment variable.
func GetClientConfig() ClientConfig {
	// Default configuration
	transportUri := "unix:///run/nfd/nfd.sock"
	if runtime.GOOS == "darwin" {
		transportUri = "unix:///var/run/nfd/nfd.sock"
	}
	config := ClientConfig{
		TransportUri: transportUri,
	}

	// Order of increasing priority
	configDirs := []string{
		"/etc/ndn",
		"/usr/local/etc/ndn",
		os.Getenv("HOME") + "/.ndn",
	}

	// Read each config file that we can find
	for _, dir := range configDirs {
		filename := dir + "/client.conf"

		file, err := os.OpenFile(filename, os.O_RDONLY, 0)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, ";") { // comment
				continue
			}

			transport := strings.TrimPrefix(line, "transport=")
			if transport != line {
				config.TransportUri = transport
			}
		}
	}

	// Environment variable overrides config file
	transportEnv := os.Getenv("NDN_CLIENT_TRANSPORT")
	if transportEnv != "" {
		config.TransportUri = transportEnv
	}

	return config
}
