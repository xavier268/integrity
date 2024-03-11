// Sign command to sign an existing biray that imports the integrity package.
package main

import (
	"flag"
	"fmt"

	"github.com/xavier268/integrity"
)

var (
	credential string
	infile     string
	outfile    string
)

func init() {
	flag.StringVar(&credential, "p", "", "specify credential string")
	flag.StringVar(&outfile, "o", "", "specify output file")

	flag.Usage = func() {
		fmt.Printf("Usage of sign (version %s)\n", integrity.VERSION)
		fmt.Println("sign [ -p credentials -o outputFile ] inputFile")
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()
	aa := flag.Args()
	if len(aa) != 1 || (len(aa) == 1 && len(aa[0]) == 0) {
		fmt.Println("There should be exactly one filename to sign")
		flag.Usage()
		return
	} else {
		infile = integrity.MustAbs(aa[0])
	}

	saved := integrity.SignBinary(infile, outfile, credential)
	fmt.Println("Saved signed binary to :", saved)
}
