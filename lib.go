// contains highlevel command for (self)signing binaries or validating signatures.
package integrity

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	// actual payload size
	payloadSize = sha512.Size
	VERSION     = "0.3"
)

// reserved space to store signature.
// it contains a delimiter, followed by actual payload
const reserve = "\x8e\xa9\xe1SA\xf6\x1ch\xb7z\xf2\xdc}\x03\xa0\x17\xf9\b\xf8\xb6ܒ\xf6\x7f\x1f\xda\xed\xfej\x8aC&\x1d\x17RN\xad\xbcQ\x1c\x84n\xcc\xc1'\x92\xc4\xf8\x91\\\xeb\xf1\xd8탧\x04.\xc0E\x1a\xfeW\xc3\xca>E\x14{\x87c\x7fR\x9c\x92\xaf7È\xb4\xd2\xc6=X\x8c\x9a\x11\xeb\x81/\x16}Y?m!%0\xabB\x9c\xb1'\xbd\x00\x85n\x94G\xeam<i\t\\\x1eA8˰G\xc3ߡ\x05\x81 \x063\xccKI\xe9@\xdfr\xa5\xaf2d%\xc5FW"

var (
	// delimiter size
	delimSize = len([]byte(reserve)) - payloadSize
)

// get data from exe file
func loadData() (data []byte) {
	if delimSize <= 40 {
		panic("delimiter size is too small")
	}
	f, err := os.Open(os.Args[0])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	data, err = io.ReadAll(f)
	if err != nil {
		panic(err)
	}
	return data
}

/*
func saveData(data []byte) (newfilename string) {
	dir, file := filepath.Split(os.Args[0])
	saveFile := filepath.Join(dir, "signed-"+file)
	f, err := os.Create(saveFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	f.Write(data)
	return saveFile
}
*/

// replace payload in place with signature, using provided credentials.
func sign(data []byte, credentials string) {

	if delimSize <= 40 {
		panic("delimiter size is too small")
	}
	// split around delimiter
	dd := bytes.Split(data, []byte(reserve)[:delimSize])
	if len(dd) != 2 {
		panic(len(dd))
	}
	if len(dd[1]) < payloadSize {
		panic(len(dd[1]))
	}

	// compute signature
	h := sha512.New()
	h.Write([]byte(credentials))
	h.Write(dd[0])
	h.Write(dd[1][payloadSize:])
	sig := h.Sum(nil)

	// replace signature in place
	for i := 0; i < payloadSize; i++ {
		data[len(dd[0])+delimSize+i] = sig[i]
	}
}

// check signature validity, true if ok.
func isValid(data []byte, credentials string) bool {

	if delimSize <= 40 {
		panic("delimiter size is too small")
	}

	// split around delimiter
	dd := bytes.Split(data, []byte(reserve)[:delimSize])
	if len(dd) != 2 {
		// // debug
		// fmt.Println("Return split : ", len(dd))
		// for i, d := range dd {
		// 	fmt.Println("Split ", i, ")\t", string(d))
		// }
		panic(len(dd))
	}
	if len(dd[1]) < payloadSize {
		panic(len(dd[1]))
	}

	// compute signature
	h := sha512.New()
	h.Write([]byte(credentials))
	h.Write(dd[0])
	h.Write(dd[1][payloadSize:])
	sig := h.Sum(nil)

	// check signature in place
	return bytes.Equal(
		data[len(dd[0])+delimSize:len(dd[0])+delimSize+payloadSize],
		sig)

}

// Produce a signed binary with provided credentials from running binary
func Sign(credentials string) (newFileName string) {
	in := MustAbs(os.Args[0])
	dir, out := filepath.Split(in)
	out = filepath.Join(dir, "signed-"+out)
	return SignBinary(in, out, credentials)
}

// Produce a signed binary with provided credentials from provided binary
func SignBinary(sourceBinaryFileName string, targetBinaryFileName string, credentials string) (newTargetFileName string) {
	sourceBinaryFileName = MustAbs(sourceBinaryFileName)

	// load binary data
	f, err := os.Open(sourceBinaryFileName)
	if err != nil {
		fmt.Printf("Cannot open source name : %s\n", sourceBinaryFileName)
		panic(err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		fmt.Println("Cannot read ", MustAbs(sourceBinaryFileName))
		panic(err)
	}
	// actual signing
	sign(data, credentials)

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

// Verify a binary for a valid signature, using provided credentials
func IsValid(credentials string) bool {
	data := loadData()
	return isValid(data, credentials)
}

func MustAbs(fn string) string {
	abs, err := filepath.Abs(fn)
	if err != nil {
		panic(err)
	}
	return abs
}
