package certify

import (
	"reflect"
	"strings"
	"testing"
)

var (
	PKEYDATA = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIL66D9bK8UInoN0xfbQ3/usWXWzHSb8cq+e2RfO6usYpoAoGCCqGSM49
AwEHoUQDQgAE8aYzn9wIIS+K4/lX6aoUQR18rGLsjKmQgIa+vtc3jwWclNJhh3tT
AsroDcdnN6haaQt3fmI56TphJF5PXCAhIQ==
-----END EC PRIVATE KEY-----
`
	RSAPKEYDATA = `-----BEGIN RSA PRIVATE KEY-----
MIIBOQIBAAJBAMqARHoSpBvmYR92JAfSf4roUoyLB9D6e/nNoIK7yjw5PvUGEHM+
uMOiIQjlqui020aj5TeuWs09ljGKhcF0nGkCAwEAAQJAZiBiaJ5WHawGd3OBoGBM
6qVYXIERpBdvxwApX0WOLOhcAJ5nYSboyppHEYTk4NgK7YuoZy61KswAU+qmy/Jw
AQIhAPHWn5ghX+VhTG/J1ZY/y13hOpj4+9Eki+MJNr7pXqXpAiEA1lvxHLYEDOev
rj4iN5/bvF6Dbl1QYrwMa582C2LPsoECIAuPpA+EwO3ZSesqLfDB2foB82gutvMX
mSxgW2KjC2hJAiA2xQ0pIdSNG5GGurdxcPXq/lckltEYOSYPRYHAjQG2gQIgZdwE
QfCCn+yOvP+oeXatjlGliCnVL95G6fA1icn4AnE=
-----END RSA PRIVATE KEY-----
`
)

func TestGetPrivateKey(t *testing.T) {
	p, err := GetPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Test created private key can be parsed", func(t *testing.T) {
		_, err := ParsePrivateKey([]byte(p.String()))
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestParsePrivateKey(t *testing.T) {
	t.Run("Test compare parsed valid private key", func(t *testing.T) {
		p, err := ParsePrivateKey([]byte(PKEYDATA))
		if err != nil {
			t.Fatal(err)
		}

		pkey := &PrivateKey{p}

		if !reflect.DeepEqual(pkey.String(), PKEYDATA) {
			t.Fatalf("\ngot %v\nwant %v\n", pkey.String(), PKEYDATA)
		}
	})

	t.Run("Test parsing unsuported rsa private key", func(t *testing.T) {
		_, err := ParsePrivateKey([]byte(RSAPKEYDATA))
		if err == nil {
			t.Fatalf("got no error, want error contains x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format")
		}
	})
}

func TestParseEmptyPrivateKeyFile(t *testing.T) {
	_, err := ParsePrivateKey([]byte(""))
	if err != nil {
		if !strings.Contains(err.Error(), "no pem data found") {
			t.Fatal("the error must contain no pem data found")
		}
	}
}
