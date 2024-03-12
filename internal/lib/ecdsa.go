package lib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
)

// Generate asymetric, der encoded, signing keys
func GenerateKeys() (privDer []byte, pubDer []byte) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Convertir la clé secrète ECDSA en ASN.1 DER encodé
	privDer, err = x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}

	// Convertir la clé publique ECDSA en ASN.1 DER encodé
	pubDer, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}

	return privDer, pubDer
}
