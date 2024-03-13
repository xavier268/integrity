// Sign command to sign an existing binary. The binary should already import the integrity package.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xavier268/integrity/internal/lib"
)

var (
	credential string
	infile     string
	outfile    string
	version    bool
	genkey     bool
)

func init() {
	flag.StringVar(&credential, "p", "", "specify credential string")
	flag.StringVar(&outfile, "o", "", "specify output file")
	flag.BoolVar(&version, "v", false, "print version and exit")
	flag.BoolVar(&genkey, "g", false, "generate a new key pair and exit")

	flag.Usage = func() {
		fmt.Printf("Usage of %s (version %s) - %s :\n", filepath.Base(os.Args[0]), lib.VERSION, lib.COPYRIGHT)
		fmt.Printf("%s [ -p credentials -o outputFile ] inputFile\n\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()
	if version {
		fmt.Println(lib.VERSION)
		return
	}
	if genkey {
		panic("todo")
	}
	aa := flag.Args()
	if len(aa) != 1 || (len(aa) == 1 && len(aa[0]) == 0) {
		fmt.Println("There should be exactly one filename to sign")
		flag.Usage()
		return
	} else {
		infile = lib.MustAbs(aa[0])
	}

	saved := lib.SignBinary(infile, outfile, credential, nil)
	fmt.Println("Saved signed binary to :", saved)
}
