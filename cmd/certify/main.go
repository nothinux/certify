package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/nothinux/certify"
	"golang.org/x/term"
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

	if *read {
		var certByte []byte
		var err error

		if len(os.Args) < 3 {
			if err := isPipe(os.Stdin); err != nil {
				log.Fatal(err)
			}

			certByte, err = io.ReadAll(os.Stdin)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			certByte, err = os.ReadFile(os.Args[2])
			if err != nil {
				log.Fatal(err)
			}
		}

		cert, err := certify.ParseCertificate(certByte)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s", certify.CertInfo(cert))
		return
	}

	if *connect {
		if len(os.Args) < 3 {
			fmt.Printf("you must provide remote host.\n")
			os.Exit(1)
		}

		result, err := tlsDial(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(certify.CertInfo(result))
		return
	}

	if *match {
		if len(os.Args) < 4 {
			fmt.Printf("you must provide pkey and cert.\n")
			os.Exit(1)
		}

		pubkey, pubcert, err := matcher(os.Args[2], os.Args[3])
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf(
			"pubkey from %s:\n%s\n\npubkey from %s:\n%s\n✅ certificate and private key match\n",
			os.Args[2],
			pubkey,
			os.Args[3],
			pubcert,
		)

		return
	}

	if *epkcs12 {
		if len(os.Args) < 5 {
			fmt.Println("you must provide [key-path] [cert-path] and [ca-path]")
			os.Exit(1)
		}

		fmt.Print("enter password: ")
		bytePass, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal(err)
		}

		// verify if cert and key has same public key
		_, _, err = matcher(os.Args[2], os.Args[3])
		if err != nil {
			log.Fatal("\n", err)
		}

		pfxData, err := getPfxData(
			os.Args[2],
			os.Args[3],
			os.Args[4],
			string(bytePass),
		)
		if err != nil {
			log.Fatal(err)
		}

		if err := os.WriteFile("client.p12", pfxData, 0644); err != nil {
			log.Fatal(err)
		}
		fmt.Println("\ncertificate exporter to client.p12")
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
