package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/nothinux/certify"
)

const usage = `Usage of certify:
certify [flag] [ip-or-dns-san] [cn:default certify] [expiry: s,m,h,d]

$ certify -init
⚡️ Initialize new CA Certificate and Key

$ certify server.local 172.17.0.1
⚡️ Generate certificate with alt name server.local and 172.17.0.1

$ certify cn:web-server
⚡️ Generate certificate with common name web-server

$ certify server.local expiry:1d
⚡️ Generate certificate expiry within 1 day

Also, you can see information from created certificate

$ certify -show server.local.pem
⚡️ Show information from certificate with name server.local.pem

You must create new CA by run -init before you can create certificate.
`

var (
	caPath    = "ca-cert.pem"
	caKeyPath = "ca-key.pem"
)

func main() {
	init := flag.Bool("init", false, "initialize new CA Certificate and Key")
	show := flag.Bool("show", false, "show information about certificate")
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage)
	}
	flag.Parse()

	if *init {
		pkey, err := generatePrivateKey(caKeyPath)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("CA private key file generated", caKeyPath)

		var cn string

		if len(os.Args) > 2 {
			if strings.Contains(os.Args[2], "cn:") {
				cn = os.Args[2]
			}
		}

		if err := generateCA(pkey.PrivateKey, cn, caPath); err != nil {
			log.Fatal(err)
		}
		fmt.Println("CA certificate file generated", caPath)
		return
	}

	if *show {
		if len(os.Args) < 3 {
			fmt.Printf("you must provide certificate path.\n")
			os.Exit(1)
		}

		f, err := os.ReadFile(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}

		cert, err := certify.ParseCertificate(f)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s", certify.CertInfo(cert))
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
