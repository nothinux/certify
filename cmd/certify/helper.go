package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nothinux/certify"
	"software.sslmate.com/src/go-pkcs12"
)

func generatePrivateKey(path string) (*certify.PrivateKey, error) {
	p, err := certify.GetPrivateKey()
	if err != nil {
		return &certify.PrivateKey{}, err
	}

	return p, store(p.String(), path)
}

func generateCA(pkey *ecdsa.PrivateKey, cn string, path string) error {
	template := certify.Certificate{
		Subject: pkix.Name{
			Organization: []string{"certify"},
			CommonName:   parseCN(cn),
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(87660 * time.Hour),
		IsCA:      true,
	}

	caCert, err := template.GetCertificate(pkey)
	if err != nil {
		return err
	}

	return store(caCert.String(), path)
}

func generateCert(pkey *ecdsa.PrivateKey, args []string) (err error) {
	iplist, dnsnames, cn, expiry, ekus := parseArgs(args)

	var parent *x509.Certificate
	var parentKey *ecdsa.PrivateKey

	// By default, If Intermediate CA exists the generated certificate
	// will be signed with intermediate CA. If not, it will be signed
	// with rootCA

	parentKey, err = getCAPrivateKey(caInterKeyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			parentKey, err = getCAPrivateKey(caKeyPath)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	parent, err = getCACert(caInterPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			parent, err = getCACert(caPath)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	template := certify.Certificate{
		Subject: pkix.Name{
			Organization: []string{"certify"},
			CommonName:   cn,
		},
		NotBefore:        time.Now(),
		NotAfter:         expiry,
		IPAddress:        iplist,
		DNSNames:         dnsnames,
		IsCA:             false,
		Parent:           parent,
		ParentPrivateKey: parentKey,
		ExtentedKeyUsage: ekus,
	}

	cert, err := template.GetCertificate(pkey)
	if err != nil {
		return err
	}

	certPath := getFilename(args, false)

	err = store(cert.String(), certPath)
	if err == nil {
		fmt.Println("Certificate file generated", certPath)
	}

	return err
}

func generateIntermediateCert(pkey *ecdsa.PrivateKey, args []string) error {
	_, _, cn, expiry, _ := parseArgs(args)

	parentKey, err := getCAPrivateKey(caKeyPath)
	if err != nil {
		return err
	}

	parent, err := getCACert(caPath)
	if err != nil {
		return err
	}

	if cn == "" {
		cn = "certify"
	}

	newCN := fmt.Sprintf("%s Intermediate", cn)

	if expiry.Unix() > parent.NotAfter.Unix() {
		return fmt.Errorf("intermediate certificate expiry date can't longer than root CA")
	}

	template := certify.Certificate{
		Subject: pkix.Name{
			Organization: []string{"certify"},
			CommonName:   newCN,
		},
		NotBefore:        time.Now(),
		NotAfter:         expiry,
		IsCA:             true,
		Parent:           parent,
		ParentPrivateKey: parentKey,
	}

	cert, err := template.GetCertificate(pkey)
	if err != nil {
		return err
	}

	err = store(cert.String(), caInterPath)
	if err == nil {
		fmt.Println("Certificate file generated", caInterPath)
	}

	return err
}

// getFilename returns path based on given args
// first it will check dnsnames, if nil, then check iplist, if iplist nil too
// it will check common name
func getFilename(args []string, key bool) string {
	iplist, dnsnames, cn, _, _ := parseArgs(args)

	var ext string
	var path string

	if key {
		ext = "-key.pem"
	} else {
		ext = ".pem"
	}

	if len(dnsnames) != 0 {
		path = fmt.Sprintf("%s%s", dnsnames[0], ext)
	} else if len(iplist) != 0 {
		path = fmt.Sprintf("%s%s", iplist[0], ext)
	} else {
		path = fmt.Sprintf("%s%s", cn, ext)
	}

	return path
}

func getCAPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	pkey, err := readPrivateKeyFile(path)
	if err != nil {
		return nil, err
	}

	return pkey, nil
}

func readPrivateKeyFile(path string) (*ecdsa.PrivateKey, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pkey, err := certify.ParsePrivateKey(f)
	if err != nil {
		return nil, err
	}

	return pkey, nil
}

func getCACert(path string) (*x509.Certificate, error) {
	c, err := readCertificateFile(path)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func readCertificateFile(path string) (*x509.Certificate, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	c, err := certify.ParseCertificate(f)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func getPfxData(pkey, cert, caCert, password string) ([]byte, error) {
	p, err := readPrivateKeyFile(pkey)
	if err != nil {
		return nil, err
	}

	c, err := readCertificateFile(cert)
	if err != nil {
		return nil, err
	}

	ca, err := readCertificateFile(caCert)
	if err != nil {
		return nil, err
	}

	pfxData, err := pkcs12.Encode(
		rand.Reader, p, c, []*x509.Certificate{ca}, password,
	)

	if err != nil {
		return nil, err
	}

	return pfxData, nil
}

// comparePublicKey returns an error if public key from certificate and public
// key from private key doesn't match
func comparePublicKey(key *ecdsa.PrivateKey, cert *x509.Certificate) (string, string, error) {
	pubkey, err := certify.GetPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}

	pubcert, err := certify.GetPublicKey(cert.PublicKey)
	if err != nil {
		return "", "", err
	}

	if pubkey != pubcert {
		return "", "", errors.New("private key doesn't match with given certificate")
	}

	return pubkey, pubcert, nil
}

func matcher(key, cert string) (string, string, error) {
	k, err := readPrivateKeyFile(key)
	if err != nil {
		return "", "", err
	}

	c, err := readCertificateFile(cert)
	if err != nil {
		return "", "", err
	}

	return comparePublicKey(k, c)
}

// parseAltNames returns parsed net.IP, DNS, Common Name and expiry date in slice format
func parseArgs(args []string) ([]net.IP, []string, string, time.Time, []x509.ExtKeyUsage) {
	var iplist []net.IP
	var dnsnames []string
	var cn string
	var expiry time.Time
	var ekus []x509.ExtKeyUsage

	for _, arg := range args[1:] {
		if net.ParseIP(arg) != nil {
			iplist = append(iplist, net.ParseIP(arg))
		} else if strings.Contains(arg, "cn:") {
			if cn == "" {
				cn = parseCN(arg)
			}
		} else if strings.Contains(arg, "expiry:") {
			expiry = parseExpiry(arg)
		} else if strings.Contains(arg, "eku:") {
			ekus = parseEKU(arg)
		} else {
			dnsnames = append(dnsnames, arg)
		}
	}

	if expiry.IsZero() {
		expiry = parseExpiry("expiry:")
	}

	if len(ekus) == 0 {
		ekus = []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		}
	}

	return iplist, dnsnames, cn, expiry, ekus
}

func parseCN(cn string) string {
	s := strings.Split(cn, ":")
	if s[1] != "" {
		return s[1]
	}

	return "certify"
}

func parseEKU(ekus string) []x509.ExtKeyUsage {
	var ExtKeyUsage []x509.ExtKeyUsage

	parsedEku := strings.Split(strings.TrimLeft(ekus, "eku:"), ",")

	for _, eku := range parsedEku {
		e := strings.ToLower(eku)
		if e == "serverauth" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		} else if e == "clientauth" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		} else if e == "any" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageAny)
		} else if e == "codesigning" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageCodeSigning)
		} else if e == "emailprotection" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
		} else if e == "ipsecendsystem" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageIPSECEndSystem)
		} else if e == "ipsectunnel" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageIPSECTunnel)
		} else if e == "ipsecuser" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageIPSECUser)
		} else if e == "timestamping" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageTimeStamping)
		} else if e == "ocspsigning" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageOCSPSigning)
		} else if e == "microsoftservergatedcrypto" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageMicrosoftServerGatedCrypto)
		} else if e == "netscapeservergatedcrypto" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageNetscapeServerGatedCrypto)
		} else if e == "microsoftcommercialcodesigning" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageMicrosoftCommercialCodeSigning)
		} else if e == "microsoftkernelcodesigning" {
			ExtKeyUsage = append(ExtKeyUsage, x509.ExtKeyUsageMicrosoftKernelCodeSigning)
		}
	}

	return ExtKeyUsage
}

func parseExpiry(expiry string) time.Time {
	format := make(map[string]time.Duration)
	format["s"] = time.Second
	format["m"] = time.Minute
	format["h"] = time.Hour
	format["d"] = 24 * time.Hour

	s := strings.Split(expiry, ":")

	for f, d := range format {
		if strings.HasSuffix(s[1], f) {
			i, err := strconv.Atoi(strings.TrimSuffix(s[1], f))
			if err != nil {
				return time.Now().Add(8766 * time.Hour)
			}

			return time.Now().Add(time.Duration(i) * d)
		}
	}

	return time.Now().Add(8766 * time.Hour)
}

// store write content to given path and returns an error
func store(c, path string) error {
	return os.WriteFile(path, []byte(c), 0640)
}

func isExist(path string) bool {
	_, err := os.Stat(path)

	return !errors.Is(err, os.ErrNotExist)
}

func isPipe(stdin *os.File) error {
	info, err := stdin.Stat()
	if err != nil {
		return err
	}

	if info.Mode()&os.ModeCharDevice != 0 || info.Size() != 0 {
		return errors.New("can't read certificate, please provide certificate path or certificate content from stdin")
	}

	return nil
}

func tlsDial(host string) (*x509.Certificate, error) {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	net, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{})
	if err != nil {
		return nil, err
	}
	defer net.Close()

	certChain := net.ConnectionState().PeerCertificates
	cert := certChain[0]

	return cert, nil
}
