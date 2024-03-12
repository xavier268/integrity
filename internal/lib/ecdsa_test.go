package lib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"strings"
	"testing"
)

func TestGenerateKeys(t *testing.T) {

	for i := 0; i < 30; i++ {

		pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		// Convertir la clé secrète ECDSA en ASN.1 DER encodé
		der, err := x509.MarshalECPrivateKey(pk)
		if err != nil {
			panic(err)
		}

		// test reading back the der-encoded key
		der2 := append(der, []byte("additionnal non significant data")...)
		pk2, err := x509.ParseECPrivateKey(der2)
		if err != nil {
			panic(err)
		}
		if !isEqual(pk, pk2) {
			panic("keys do not match")
		}

		// sign message
		msg := "hello, world" + strings.Repeat("iuy", 50)
		hash := sha512.Sum512([]byte(msg))
		sig, err := ecdsa.SignASN1(rand.Reader, pk, hash[:])
		if err != nil {
			panic(err)
		}

		if len(sig) > payloadSize {
			t.Logf("Signature size %d", len(sig))
			panic("signature too long to fit in payload")
		}

		//verify signature
		valid := ecdsa.VerifyASN1(&pk2.PublicKey, hash[:], sig)
		if !valid {
			panic("could not verify signature")
		}
	}

}

// isEqual compares two ECDSA private keys for equality.
func isEqual(key1, key2 *ecdsa.PrivateKey) bool {
	// First, check if they use the same curve
	if key1.PublicKey.Curve != key2.PublicKey.Curve {
		return false
	}

	// Compare the private scalar values (D fields)
	return key1.D.Cmp(key2.D) == 0
}
