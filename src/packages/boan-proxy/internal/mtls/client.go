package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// NewHTTPClient returns an *http.Client configured with optional mTLS.
// If certFile and keyFile are empty, returns a plain TLS client with optional custom CA.
func NewHTTPClient(certFile, keyFile, caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{}

	if caFile != "" {
		caPem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("mtls: read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPem) {
			return nil, fmt.Errorf("mtls: no valid certificates in CA file %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("mtls: load client keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}, nil
}
