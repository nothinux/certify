package certify

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
)

// GetPublicKey returns string of pem encoded structure from given public key
func GetPublicKey(pub interface{}) (string, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	var w bytes.Buffer
	if err := pem.Encode(&w, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}); err != nil {
		return "", err
	}

	return w.String(), err
}

func parseExtKeyUsage(ekus []x509.ExtKeyUsage) string {
	var extku []string

	for _, eku := range ekus {
		if eku == x509.ExtKeyUsageAny {
			extku = append(extku, "Any Usage")
		} else if eku == x509.ExtKeyUsageClientAuth {
			extku = append(extku, "TLS Web Client Authentication")
		} else if eku == x509.ExtKeyUsageServerAuth {
			extku = append(extku, "TLS Web Server Authentication")
		} else {
			extku = append(extku, strconv.Itoa(int(eku)))
		}
	}

	return strings.Join(extku, ", ")
}

func formatKeyIDWithColon(id []byte) string {
	var s string

	for i, c := range id {
		if i > 0 {
			s += ":"
		}
		s += fmt.Sprintf("%02x", c)
	}

	return s
}
