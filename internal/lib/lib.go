// internal librairies for signing or validating signatures for access contriol to binaries
package lib

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"

	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	VERSION   = "0.4"
	COPYRIGHT = "(c) Xavier Gandillot 2024"
)

// reserved space to store signature.
// it contains a delimiter, followed by actual payload
const reserve = "\x8e\xa9\xe1SA\xf6\x1ch\xb7z\xf2\xdc}\x03\xa0\x17\xf9\b\xf8\xb6ܒ\xf6\x7f\x1f\xda\xed\xfej\x8aC&\x1d\x17RN\xad\xbcQ\x1c\x84n\xcc\xc1'\x92\xc4\xf8\x91\\\xeb\xf1\xd8탧\x04.\xc0E\x1a\xfeW\xc3\xca>E\x14{\x87c\x7fR\x9c\x92\xaf7È\xb4\xd2\xc6=X\x8c\x9a\x11\xeb\x81/\x16}Y?m!%0\xabB\x9c\xb1'\xbd\x00\x85n\x94G\xeam<i\t\\\x1eA8˰G\xc3ߡ\x05\x81 \x063\xccKI\xe9@\xdfr\xa5\xaf2d%\xc5FW"

var (

	// actual payload size.
	// enough for a der encoded P-256 signature that starts with 64bytes,
	// plus der encoding overhead, so less than 80,
	// while at least enough for the sha512 hash.
	// Plus the length of what is stored, in 2 bytes.
	payloadSize = 2 + max(80, sha512.Size)
	// delimiter size
	delimSize = len([]byte(reserve)) - payloadSize
)

// load data from binary filename
func loadDataBinary(fileName string) (data []byte) {
	if delimSize <= 40 {
		panic("delimiter size is too small")
	}
	f, err := os.Open(fileName)
	if err != nil {
		fmt.Println("Cannot open file ", MustAbs(fileName))
		panic(err)
	}
	defer f.Close()
	data, err = io.ReadAll(f)
	if err != nil {
		fmt.Println("Cannot load data from ", MustAbs(fileName))
		panic(err)
	}
	return data
}

// get data from current exe file
func loadData() (data []byte) {
	return loadDataBinary(os.Args[0])
}

// replace payload in place with signature, using provided credentials.
func sign(data []byte, credentials string, pk *ecdsa.PrivateKey) {

	var err error

	if delimSize <= 40 {
		panic("delimiter size is too small")
	}
	// split around delimiter
	dd := bytes.Split(data, []byte(reserve)[:delimSize])
	if len(dd) != 2 {
		fmt.Println("This file does not seem to import the integrity package. It cannot be signed nor validated.")
		panic(len(dd))
	}
	if len(dd[1]) < payloadSize {
		fmt.Println("Invalid binary file format.")
		panic(len(dd[1]))
	}

	// compute hash, excluding delimiter and payload
	hash := Hash([]byte(credentials), dd[0], dd[1][payloadSize:])

	// sign hash
	var sig []byte
	if pk != nil {
		sig, err = ecdsa.SignASN1(rand.Reader, pk, hash[:])
		if err != nil {
			fmt.Println("could not sign with provided private key")
			panic(err)
		}
		if len(sig) > payloadSize {
			fmt.Printf("signature is too large to fit in payload (%d > %d)\n", len(sig), payloadSize)
			panic(len(sig))
		}
	} else {
		sig = hash
	}

	// prepend length on 4 bytes to sig
	var buf [4]byte
	buf[0] = byte(len(sig))
	buf[1] = byte(len(sig) >> 8)
	sig = append(buf[:], sig...)

	// replace signature in place
	copy(data[len(dd[0])+delimSize:], sig)

}

// check signature validity, true if ok.
// if pk is nil, hash is used directly.
func isValid(data []byte, credentials string, pk *ecdsa.PublicKey) bool {

	if delimSize <= 40 {
		panic("delimiter size is too small")
	}

	// split around delimiter
	dd := bytes.Split(data, []byte(reserve)[:delimSize])
	if len(dd) != 2 {
		fmt.Printf("Internal validating error.")
		panic(len(dd))
	}
	if len(dd[1]) < payloadSize {
		fmt.Printf("Invalid binary file format.")
		panic(len(dd[1]))
	}

	// compute hash, excluding delimiter and payload
	hash := Hash([]byte(credentials), dd[0], dd[1][payloadSize:])

	// capture the payload from the data
	sig := data[len(dd[0])+delimSize : len(dd[0])+delimSize+payloadSize]

	// extract signature from payload. The first 4 bytes represents the length.
	l := int(sig[0]) | int(sig[1])<<8
	if l > payloadSize {
		// invalid length. Don't even try ...
		return false
	}
	sig = sig[4 : l+4]

	// Verify signature validity
	var valid bool
	if pk == nil {
		valid = bytes.Equal(sig, hash)
	} else {
		valid = ecdsa.VerifyASN1(pk, hash, sig)
	}

	return valid
}

// Produce a signed binary with provided credentials from provided binary
// If the private, der encoded, key is not provided, directly use the hash without encoding.
func SignBinary(sourceBinaryFileName string, targetBinaryFileName string, credentials string, privateKeyDer []byte) (newTargetFileName string) {
	var err error
	sourceBinaryFileName = MustAbs(sourceBinaryFileName)

	// load source binary data
	data := loadDataBinary(sourceBinaryFileName)

	// decode private key
	var pk *ecdsa.PrivateKey
	if len(privateKeyDer) != 0 {
		pk, err = x509.ParseECPrivateKey(privateKeyDer)
		if err != nil {
			fmt.Println("Cannot decode private key")
			panic(err)
		}
	}

	// actual signing
	sign(data, credentials, pk)

	// save to provided file name, default to reasonable value if empty string
	if targetBinaryFileName == "" {
		dir, file := filepath.Split(sourceBinaryFileName)
		targetBinaryFileName = filepath.Join(dir, "signed-"+file)
	}

	tf, err := os.Create(targetBinaryFileName)
	if err != nil {
		fmt.Println("Cannot open ", MustAbs(targetBinaryFileName))
		panic(err)
	}
	defer tf.Close()
	tf.Write(data)
	return MustAbs(targetBinaryFileName)
}

// Self-verify a binary for a valid signature, using provided credentials
func IsValid(credentials string, publicKeyDer []byte) bool {
	var pk *ecdsa.PublicKey
	var ok bool

	if publicKeyDer != nil {
		pkx, err := x509.ParsePKIXPublicKey(publicKeyDer)
		if err != nil {
			fmt.Println("Cannot decode public key")
			panic(err)
		}
		pk, ok = pkx.(*ecdsa.PublicKey)
		if !ok {
			fmt.Println("Cannot convert public key to ecsda key")
			panic(publicKeyDer)
		}
	}
	data := loadData()
	return isValid(data, credentials, pk)
}

// Get Absolute file path.
func MustAbs(fn string) string {
	abs, err := filepath.Abs(fn)
	if err != nil {
		panic(err)
	}
	return abs
}

// Hash function utility
func Hash(datas ...[]byte) []byte {
	h := sha512.New()
	for _, data := range datas {
		h.Write(data)
	}
	return h.Sum(nil)
}
