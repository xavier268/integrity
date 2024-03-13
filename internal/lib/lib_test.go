package lib

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestSignValid(t *testing.T) {

	var pubK *ecdsa.PublicKey
	var privK *ecdsa.PrivateKey
	var ok bool
	var err error

	for i := 0; i < 2; i++ {

		fmt.Println("\nKeys are :")
		fmt.Println(privK)
		fmt.Println(pubK)

		data := []byte("FIRST PART" + reserve + "SECOND PART")
		// fmt.Println("Data : ", string(data))
		// fmt.Println("Delimiter :", string([]byte(reserve)[:delimSize]))

		if isValid(data, "password", pubK) {
			t.Error("should not be signed already")
		}
		if isValid(data, "", pubK) {
			t.Error("should not be signed already")
		}

		// signing !
		sign(data, "password", privK)
		// fmt.Println("Signature performed")
		// fmt.Println(string(data))

		if !isValid(data, "password", pubK) {
			t.Error("cannot confirm signature")
		}
		if isValid(data, "wrong password", pubK) {
			t.Error("should not accept invalid credentials")
		}
		if isValid(data, "", pubK) {
			t.Error("should not accept invalid credentials")
		}

		privDer := GenerateKeys()
		pubDer := DerivePubKey(privDer)

		// Parse private and public keys
		privK, err = x509.ParseECPrivateKey(privDer)
		if err != nil {
			panic(err)
		}
		ppubK, err := x509.ParsePKIXPublicKey(pubDer)
		if err != nil {
			panic(err)
		}
		pubK, ok = ppubK.(*ecdsa.PublicKey)
		if !ok {
			panic("invalid public key")
		}

	}

}

func TestGenerateRandomString(t *testing.T) {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	data := make([]byte, payloadSize+80)
	for i := range data {
		data[i] = byte(rnd.Intn(256))
	}
	fmt.Printf("\n%#v\n", string(data))
}
