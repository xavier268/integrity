package util

import (
	"bytes"
	"crypto/sha512"
	"io"
	"os"
	"path/filepath"
)

const (
	// actual payload size
	payloadSize = sha512.Size
	VERSION     = "0.2"
)

// reserved space to store signature.
// it contains a delimiter, followed by actual payload
const reserve = `dfvmlk!jqer$£pàç_"'l_ npàç'_(- n^àç_5
	4qze'y(àçç,  56z7-y54354erth.354erth3654 ni)àçàz')
	peoirtpoziertùpoizerùtpoizeprùoiùpoizer,)àç'(-àçf)
	çà_è(éàçnnn ==)é&)à²)ezp===)==)à=)"'("'----'(-'é(à`

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

func saveData(data []byte) {
	dir, file := filepath.Split(os.Args[0])
	saveFile := filepath.Join(dir, "signed-"+file)
	f, err := os.Create(saveFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	f.Write(data)
}

// replace payload in place with signature
func sign(data []byte) {

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

	// compute signature and replace
	h := sha512.New()
	h.Write(dd[0])
	h.Write(dd[1][payloadSize:])
	sig := h.Sum(nil)

	// replace signature in place
	for i := 0; i < payloadSize; i++ {
		data[len(dd[0])+delimSize+i] = sig[i]
	}
}

// check signature validity, true if ok.
func isValid(data []byte) bool {

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

	// compute signature and replace
	h := sha512.New()
	h.Write(dd[0])
	h.Write(dd[1][payloadSize:])
	sig := h.Sum(nil)

	// check signature in place
	return bytes.Equal(
		data[len(dd[0])+delimSize:len(dd[0])+delimSize+payloadSize],
		sig)

}

// Produce a signe binary
func Sign() {
	data := loadData()
	sign(data)
	saveData(data)
}

// Verify a binary for a vali signature
func IsValid() bool {
	data := loadData()
	return isValid(data)
}
