package main

import (
	"crypto/ecdsa"
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
		NotAfter:  time.Now().Add(8766 * time.Hour),
		IsCA:      true,
	}

	caCert, err := template.GetCertificate(pkey)
	if err != nil {
		return err
	}

	return store(caCert.String(), path)
}

func generateCert(pkey *ecdsa.PrivateKey, args []string) error {
	iplist, dnsnames, cn, expiry := parseArgs(args)

	parentKey, err := getCAPrivateKey()
	if err != nil {
		return err
	}

	parent, err := getCACert()
	if err != nil {
		return err
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

// getFilename returns path based on given args
// first it will check dnsnames, if nil, then check iplist, if iplist nil too
// it will check common name
func getFilename(args []string, key bool) string {
	iplist, dnsnames, cn, _ := parseArgs(args)

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

func getCAPrivateKey() (*ecdsa.PrivateKey, error) {
	f, err := os.ReadFile("ca-key.pem")
	if err != nil {
		return nil, err
	}

	pkey, err := certify.ParsePrivateKey(f)
	if err != nil {
		return nil, err
	}

	return pkey, nil
}

func getCACert() (*x509.Certificate, error) {
	f, err := os.ReadFile("ca-cert.pem")
	if err != nil {
		return nil, err
	}

	c, err := certify.ParseCertificate(f)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// parseAltNames returns parsed net.IP, DNS, Common Name and expiry date in slice format
func parseArgs(args []string) ([]net.IP, []string, string, time.Time) {
	var iplist []net.IP
	var dnsnames []string
	var cn string
	var expiry time.Time

	for _, arg := range args[1:] {
		if net.ParseIP(arg) != nil {
			iplist = append(iplist, net.ParseIP(arg))
		} else if strings.Contains(arg, "cn:") {
			if cn == "" {
				cn = parseCN(arg)
			}
		} else if strings.Contains(arg, "expiry:") {
			expiry = parseExpiry(arg)
		} else {
			dnsnames = append(dnsnames, arg)
		}
	}

	if expiry.IsZero() {
		expiry = parseExpiry("")
	}

	return iplist, dnsnames, cn, expiry
}

func parseCN(cn string) string {
	if strings.Contains(cn, "cn:") {
		s := strings.Split(cn, ":")
		if s[1] != "" {
			return s[1]
		}
	}

	return "certify"
}

func parseExpiry(expiry string) time.Time {
	format := make(map[string]time.Duration)
	format["s"] = time.Second
	format["m"] = time.Minute
	format["h"] = time.Hour
	format["d"] = 24 * time.Hour

	if strings.Contains(expiry, "expiry:") {
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
