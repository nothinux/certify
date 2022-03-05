package certify

import (
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
)

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
