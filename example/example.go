package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/xavier268/integrity"
)

var passw string

func init() {
	flag.StringVar(&passw, "p", "", "access password")
}

func main() {

	flag.Parse()

	fmt.Println("Hello Word")
	fmt.Println(os.Args[0])

	if integrity.IsValid(passw) { // validate credentials
		fmt.Println("Access IS be granted")
	} else { // sign with credentials
		fmt.Println("Access CANNOT be granted")
	}

}
