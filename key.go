package certify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// PrivateKey hold private key
type PrivateKey struct {
	*ecdsa.PrivateKey
}

// GetPrivateKey returns struct PrivateKey containing the private key
func GetPrivateKey() (*PrivateKey, error) {
	pkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return &PrivateKey{}, err
	}

	return &PrivateKey{
		pkey,
	}, nil
}

// String returns string of private key in pem encoded format
func (p *PrivateKey) String() string {
	b, err := x509.MarshalECPrivateKey(p.PrivateKey)
	if err != nil {
		return ""
	}

	var w bytes.Buffer
	if err := pem.Encode(&w, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: b,
	}); err != nil {
		return ""
	}

	return w.String()
}

// ParsePrivatekey parse given []byte private key to struct *ecdsa.PrivateKey
func ParsePrivateKey(pkey []byte) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode(pkey)
	if b == nil {
		return &ecdsa.PrivateKey{}, fmt.Errorf("no pem data found")
	}

	u, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}

	return u, nil
}
