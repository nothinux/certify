package certify

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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

func parseKeyUsage(ku x509.KeyUsage) []string {
	usages := []string{}

	if ku&x509.KeyUsageDigitalSignature > 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment > 0 {
		usages = append(usages, "Content Commitment")
	}
	if ku&x509.KeyUsageDataEncipherment > 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment > 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement > 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign > 0 {
		usages = append(usages, "Cert Sign")
	}
	if ku&x509.KeyUsageCRLSign > 0 {
		usages = append(usages, "CRL Sign")
	}
	if ku&x509.KeyUsageEncipherOnly > 0 {
		usages = append(usages, "Enchiper Only")
	}
	if ku&x509.KeyUsageDecipherOnly > 0 {
		usages = append(usages, "Dechiper Only")
	}

	return usages
}

func parseExtKeyUsage(ekus []x509.ExtKeyUsage) string {
	var extku []string

	for _, eku := range ekus {
		if eku == x509.ExtKeyUsageAny {
			extku = append(extku, "Any Extended Key Usage")
		} else if eku == x509.ExtKeyUsageClientAuth {
			extku = append(extku, "TLS Web Client Authentication")
		} else if eku == x509.ExtKeyUsageServerAuth {
			extku = append(extku, "TLS Web Server Authentication")
		} else if eku == x509.ExtKeyUsageCodeSigning {
			extku = append(extku, "Code Signing")
		} else if eku == x509.ExtKeyUsageEmailProtection {
			extku = append(extku, "E-mail Protection")
		} else if eku == x509.ExtKeyUsageIPSECEndSystem {
			extku = append(extku, "IPSec End System")
		} else if eku == x509.ExtKeyUsageIPSECTunnel {
			extku = append(extku, "IPSec Tunnel")
		} else if eku == x509.ExtKeyUsageIPSECUser {
			extku = append(extku, "IPSec User")
		} else if eku == x509.ExtKeyUsageTimeStamping {
			extku = append(extku, "Time Stamping")
		} else if eku == x509.ExtKeyUsageOCSPSigning {
			extku = append(extku, "OCSP Signing")
		} else if eku == x509.ExtKeyUsageMicrosoftServerGatedCrypto {
			extku = append(extku, "Microsoft Server Gated Crypto")
		} else if eku == x509.ExtKeyUsageNetscapeServerGatedCrypto {
			extku = append(extku, "Netscape Server Gated Crypto")
		} else if eku == x509.ExtKeyUsageMicrosoftCommercialCodeSigning {
			extku = append(extku, "Microsoft Commercial Code Signing")
		} else if eku == x509.ExtKeyUsageMicrosoftKernelCodeSigning {
			extku = append(extku, "1.3.6.1.4.1.311.61.1.1")
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
