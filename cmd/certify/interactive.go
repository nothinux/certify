package main

import (
	"fmt"
	"os"

	"github.com/manifoldco/promptui"
)

const (
	optCreateCA      = "Create CA"
	optCreateIntCert = "Create Intermediate CA"
	optCreateCert    = "Create Certificate"
)

var (
	confirmSignPrompt  = promptui.Prompt{Label: "Certificate will be signed with CA or Intermediate CA in current directory", IsConfirm: true}
	commonNamePrompt   = promptui.Prompt{Label: "Common Name", Default: "Certify"}
	organizationPrompt = promptui.Prompt{Label: "Organization", Default: "Certify"}
	sanPrompt          = promptui.Prompt{Label: "Subject Alternative Names", Default: "Certify"}
	startPrompt        = promptui.Select{Label: "Certify", Items: []string{optCreateCA, optCreateCert, optCreateIntCert}}
	expiryPrompt       = promptui.Select{Label: "Expiry", Items: []string{"30d", "90d", "365d", "3650d"}, CursorPos: 2}
)

func promptErr(err error) {
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}
}

func setCertifyFlag(flagKey, flagVal string) string {
	return fmt.Sprintf("%s:%s", flagKey, flagVal)
}

func runWizard() error {
	_, result, err := startPrompt.Run()
	promptErr(err)

	switch result {
	case optCreateCA:
		cn, err := commonNamePrompt.Run()
		promptErr(err)

		og, err := organizationPrompt.Run()
		promptErr(err)

		_, expiry, err := expiryPrompt.Run()
		promptErr(err)

		if err := initCA([]string{setCertifyFlag("cn", cn), setCertifyFlag("o", og), setCertifyFlag("expiry", expiry)}); err != nil {
			return err
		}

	case optCreateIntCert:
		cn, err := commonNamePrompt.Run()
		promptErr(err)

		og, err := organizationPrompt.Run()
		promptErr(err)

		_, expiry, err := expiryPrompt.Run()
		promptErr(err)

		_, err = confirmSignPrompt.Run()
		promptErr(err)

		if err := createIntermediateCertificate([]string{setCertifyFlag("cn", cn), setCertifyFlag("o", og), setCertifyFlag("expiry", expiry)}); err != nil {
			return err
		}

	case optCreateCert:
		cn, err := commonNamePrompt.Run()
		promptErr(err)

		og, err := organizationPrompt.Run()
		promptErr(err)

		san, err := sanPrompt.Run()
		promptErr(err)

		_, expiry, err := expiryPrompt.Run()
		promptErr(err)

		_, err = confirmSignPrompt.Run()
		promptErr(err)

		if err := createCertificate([]string{
			setCertifyFlag("cn", cn),
			setCertifyFlag("o", og),
			setCertifyFlag("expiry", expiry),
			san,
		}); err != nil {
			return err
		}
	}

	return nil
}
