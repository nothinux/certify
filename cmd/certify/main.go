package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

var usage = `             _   _ ___     
 ___ ___ ___| |_|_|  _|_ _ 
|  _| -_|  _|  _| |  _| | |
|___|___|_| |_| |_|_| |_  |
                      |___| Certify v%s

Usage of certify:
certify [flag] [ip-or-dns-san] [cn:default certify] [eku:default serverAuth,clientAuth] [expiry:default 1y s,m,h,d]

$ certify server.local 172.17.0.1 cn:web-server eku:serverAuth expiry:1d

Flags:
  -init
	Initialize new CA Certificate and Key
  -read  <filename>
	Read certificate information from file server.local.pem
  -connect  <host:443>
	Show certificate information from remote host
  -export-p12  <cert> <private-key> <ca-cert>
	Generate client.p12 pem file containing certificate, private key and ca certificate
  -match  <private-key> <cert>
	Verify cert-key.pem and cert.pem has same public key
`

var (
	caPath     = "ca-cert.pem"
	caKeyPath  = "ca-key.pem"
	Version    = "No version provided"
	initialize = flag.Bool("init", false, "initialize new CA Certificate and Key")
	read       = flag.Bool("read", false, "read information from certificate")
	match      = flag.Bool("match", false, "check if private key match with certificate")
	ver        = flag.Bool("version", false, "see program version")
	connect    = flag.Bool("connect", false, "show information about certificate on remote host")
	epkcs12    = flag.Bool("export-p12", false, "export certificate and key to pkcs12 format")
)

func main() {
	flag.Usage = func() {
		showUsage := fmt.Sprintf(usage, Version)
		fmt.Fprint(flag.CommandLine.Output(), showUsage)
	}
	flag.Parse()

	if *ver {
		fmt.Printf("Certify version v%s\n", Version)
		return
	}

	if *initialize {
		if err := initCA(os.Args); err != nil {
			log.Fatal(err)
		}
		return
	}

	if *read {
		cert, err := readCertificate(os.Args, os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", cert)
		return
	}

	if *connect {
		result, err := readRemoteCertificate(os.Args)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(result)
		return
	}

	if *match {
		if err := matchCertificate(os.Args); err != nil {
			log.Fatal(err)
		}
		return
	}

	if *epkcs12 {
		exportCertificate(os.Args)
		return
	}

	if len(os.Args) < 2 {
		fmt.Printf("you must provide at least two argument.\n\n")
		fmt.Fprint(flag.CommandLine.Output(), usage)
		os.Exit(1)
	}

	if !isExist(caPath) || !isExist(caKeyPath) {
		log.Fatal("error CA Certificate or Key is not exists, run -init to create it.")
	}

	keyPath := getFilename(os.Args, true)

	pkey, err := generatePrivateKey(keyPath)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Private key file generated", keyPath)

	if err := generateCert(pkey.PrivateKey, os.Args); err != nil {
		log.Fatal(err)
	}
}
