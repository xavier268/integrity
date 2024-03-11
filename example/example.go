// example of validating access to a simple program
package main

import (
	"flag"
	"fmt"

	"github.com/xavier268/integrity"
)

var passw string

func init() {
	flag.StringVar(&passw, "p", "", "access password")
}

func main() {

	flag.Parse()

	if !integrity.IsValid(passw) { // validate credentials
		fmt.Println("Access is denied")
		return
	}

	// Access is granted !
	fmt.Println("Access IS granted")
	// ... do things ...

}
