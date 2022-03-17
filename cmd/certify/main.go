package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/nothinux/certify"
	"golang.org/x/term"
)

const usage = `             _   _ ___     
 ___ ___ ___| |_|_|  _|_ _ 
|  _| -_|  _|  _| |  _| | |
|___|___|_| |_| |_|_| |_  |
                      |___|

Usage of certify:
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
⚡️ Show certificate information with filename server.local.pem

$ certify -connect google.com:443
⚡️ Show certificate information from remote host

You must create new CA by run -init before you can create certificate.
`

var (
	caPath    = "ca-cert.pem"
	caKeyPath = "ca-key.pem"
	Version   = "No version provided"
)

func main() {
	init := flag.Bool("init", false, "initialize new CA Certificate and Key")
	show := flag.Bool("show", false, "show information about certificate")
	ver := flag.Bool("version", false, "see program version")
	connect := flag.Bool("connect", false, "show information about certificate on remote host")
	epkcs12 := flag.Bool("export-p12", false, "export certificate and key to pkcs12 format")
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage)
	}
	flag.Parse()

	if *ver {
		fmt.Printf("Certifify version v%s\n", Version)
		return
	}

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
