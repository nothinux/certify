package certify

import (
	"reflect"
	"testing"
)

var (
	PKEYDATA = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIL66D9bK8UInoN0xfbQ3/usWXWzHSb8cq+e2RfO6usYpoAoGCCqGSM49
AwEHoUQDQgAE8aYzn9wIIS+K4/lX6aoUQR18rGLsjKmQgIa+vtc3jwWclNJhh3tT
AsroDcdnN6haaQt3fmI56TphJF5PXCAhIQ==
-----END EC PRIVATE KEY-----
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
	p, err := ParsePrivateKey([]byte(PKEYDATA))
	if err != nil {
		t.Fatal(err)
	}

	pkey := &PrivateKey{p}

	t.Run("Test compare parsed private key", func(t *testing.T) {
		if !reflect.DeepEqual(pkey.String(), PKEYDATA) {
			t.Fatalf("\ngot %v\nwant %v\n", pkey.String(), PKEYDATA)
		}
	})
}
