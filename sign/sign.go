// sign command to sign an existing binary.
// The signed binary should already import the "valid" package with the corresponding key.
//
// Syntax : sign [ options ... ] [executablefile/to/sign]
//
// -h
//
//	print help and exit
//
// -id
//
//	print key id
//
// -o string
//
//	specify output file
//
// -p string
//
//	specify credential string
//
// -pub string
//
//	save public key file
//
// -sec string
//
//	generate new secret key file
//
// -v    print version and exit
package main

//go:generate go run github.com/xavier268/integrity/sign -sec sec.der -pub "../valid/pub.der"

import (
	_ "embed"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xavier268/integrity/internal/lib"
)

// import the secret key in der format.
// The file can be completely empty, in which case,
// the hash is directly used without encryption.
//
//go:embed sec.der
var secDer []byte

var (
	credential string
	infile     string
	outfile    string
	version    bool
	secFile    string
	pubFile    string
	help       bool
	id         bool
)

func init() {
	flag.StringVar(&credential, "p", "", "specify credential string")
	flag.StringVar(&outfile, "o", "", "specify output file")
	flag.BoolVar(&version, "v", false, "print version and exit")
	flag.StringVar(&secFile, "sec", "", "generate new secret key file")
	flag.StringVar(&pubFile, "pub", "", "save public key file")
	flag.BoolVar(&help, "h", false, "print help and exit")
	flag.BoolVar(&id, "id", false, "print key id")

	flag.Usage = func() {
		fmt.Printf("Usage of %s (version %s) - %s :\n", filepath.Base(os.Args[0]), lib.VERSION, lib.COPYRIGHT)
		fmt.Printf("%s [ options ... ] [executablefile/to/sign]\n\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
}

func main() {

	flag.Parse()

	if version {
		fmt.Println(lib.VERSION)
		return
	}

	if help {
		flag.Usage()
		return
	}

	// regenerate secret key file
	if len(secFile) > 0 {
		secFile = lib.MustAbs(secFile)
		sf, err := os.Create(secFile)
		if err != nil {
			fmt.Printf("Could not create %s : %v\n", secFile, err)
			panic(err)
		}
		defer sf.Close()
		secDer = lib.GenerateKeys()
		_, err = sf.Write(secDer)
		if err != nil {
			fmt.Printf("Could not write to %s : %v\n", secFile, err)
			panic(err)
		}
		sf.Close() // in case we crash later on ..
	}

	// save latest known public file
	if len(pubFile) > 0 {
		var pubDer []byte

		pubFile = lib.MustAbs(pubFile)
		pf, err := os.Create(pubFile)
		if err != nil {
			fmt.Printf("Could not create %s : %v\n", pubFile, err)
			panic(err)
		}
		defer pf.Close()

		// derive pubKey from existing secret key
		// empty keys are handled by DerivePubKey
		pubDer = lib.DerivePubKey(secDer)

		_, err = pf.Write(pubDer)
		if err != nil {
			fmt.Printf("Could not write to %s : %v\n", pubFile, err)
			panic(err)
		}
		pf.Close() // in case we crash later on ..
	}

	if id {
		fmt.Println("Using key :", KeyId())
	}

	if len(outfile) == 0 {
		outfile = infile
	}

	// read file to sign
	aa := flag.Args()
	if len(aa) != 1 || (len(aa) == 1 && len(aa[0]) == 0) {
		return
	} else {
		infile = lib.MustAbs(aa[0])
	}

	if len(secDer) == 0 {
		fmt.Println("No secret key provided, using the hash directly")
		secDer = nil
	}
	saved := lib.SignBinary(infile, outfile, credential, secDer)

	// Make saved file executable
	os.Chmod(saved, 0755)

	fmt.Printf("File %s was signed with %s and saved to  %s\n", infile, KeyId(), saved)
}

// return ID of the key currently used
func KeyId() string {
	return lib.KeyId(lib.DerivePubKey(secDer))
}
