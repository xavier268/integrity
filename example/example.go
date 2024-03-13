// example of validating access to a simple program
package main

import (
	"flag"
	"fmt"

	"github.com/xavier268/integrity/valid"
)

var passw string

func init() {
	flag.StringVar(&passw, "p", "", "access password")
}

func main() {

	flag.Parse()

	if !valid.IsValid(passw) { // validate credentials
		fmt.Println("Access is DENIED")
		return
	}

	// Access is granted !
	fmt.Println("Access is GRANTED")
	// ... do things ...

}
