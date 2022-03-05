package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"os"
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
	iplist, dnsnames, cn := parseAltNames(args)

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
		NotAfter:         time.Now().Add(8766 * time.Hour),
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
	iplist, dnsnames, cn := parseAltNames(args)

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

// parseAltNames returns parsed net.IP, DNS and Common Name in slice format
func parseAltNames(args []string) ([]net.IP, []string, string) {
	var iplist []net.IP
	var dnsnames []string
	var cn string

	for _, arg := range args[1:] {
		if net.ParseIP(arg) != nil {
			iplist = append(iplist, net.ParseIP(arg))
		} else if strings.Contains(arg, "cn:") {
			if cn == "" {
				cn = parseCN(arg)
			}
		} else {
			dnsnames = append(dnsnames, arg)
		}
	}

	return iplist, dnsnames, cn
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

// store write content to given path and returns an error
func store(c, path string) error {
	return os.WriteFile(path, []byte(c), 0640)
}

func isExist(path string) bool {
	_, err := os.Stat(path)

	return !errors.Is(err, os.ErrNotExist)
}
