package lib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
)

// Generate asymetric, der encoded, signing keys
func GenerateKeys() (privDer []byte) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Convertir la clé secrète ECDSA en ASN.1 DER encodé
	privDer, err = x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}

	return privDer
}

// Derive public key from private key
func DerivePubKey(secKeyDer []byte) (pubKeyDer []byte) {
	if len(secKeyDer) == 0 {
		return nil
	}
	privateKey, err := x509.ParseECPrivateKey(secKeyDer)
	if err != nil {
		panic(err)
	}

	pubKeyDer, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}

	return pubKeyDer
}
