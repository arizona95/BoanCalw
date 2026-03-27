package tls

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

const defaultMaxCache = 1024

type cacheEntry struct {
	host string
	cert *tls.Certificate
	elem *list.Element
}

type CA struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	mu       sync.Mutex
	cache    map[string]*cacheEntry
	lru      *list.List
	maxCache int
}

func LoadOrCreateCA(certPath, keyPath string) (*CA, error) {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return generateCA(certPath, keyPath)
	}
	return loadCA(certPath, keyPath)
}

func (ca *CA) IssueForHost(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if entry, ok := ca.cache[host]; ok {
		ca.lru.MoveToFront(entry.elem)
		return entry.cert, nil
	}
	c, err := ca.issue(host)
	if err != nil {
		return nil, err
	}
	ca.addToCache(host, c)
	return c, nil
}

func (ca *CA) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

func (ca *CA) CACert() *x509.Certificate {
	return ca.cert
}

func (ca *CA) CacheSize() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return len(ca.cache)
}

func (ca *CA) addToCache(host string, cert *tls.Certificate) {
	if ca.lru.Len() >= ca.maxCache {
		oldest := ca.lru.Back()
		if oldest != nil {
			evicted := oldest.Value.(*cacheEntry)
			ca.lru.Remove(oldest)
			delete(ca.cache, evicted.host)
		}
	}
	elem := ca.lru.PushFront(host)
	ca.cache[host] = &cacheEntry{host: host, cert: cert, elem: elem}
}

func (ca *CA) issue(host string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &priv.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}, nil
}

func generateCA(certPath, keyPath string) (*CA, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "BoanClaw CA", Organization: []string{"Samsung SDS"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	if err := writeCertPEM(certPath, der); err != nil {
		return nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyBytes); err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	return &CA{
		cert:     cert,
		key:      priv,
		cache:    make(map[string]*cacheEntry),
		lru:      list.New(),
		maxCache: defaultMaxCache,
	}, nil
}

func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &CA{
		cert:     cert,
		key:      key,
		cache:    make(map[string]*cacheEntry),
		lru:      list.New(),
		maxCache: defaultMaxCache,
	}, nil
}

func writeCertPEM(path string, der []byte) error {
	return writePEM(path, "CERTIFICATE", der)
}

func writePEM(path, typ string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: data})
}

func randomSerial() *big.Int {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return new(big.Int).SetBytes(b)
}
