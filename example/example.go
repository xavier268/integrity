package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/xavier268/integrity"
)

func main() {

	fmt.Println("Hello Word")
	fmt.Println(os.Args[0])

	if integrity.IsValid("passw") { // validate credentials
		fmt.Println("This executable is correctly signed")
	} else { // sign with credentials
		fmt.Println("This executable is not correctly signed")
		sf := integrity.Sign("passw")
		os.Rename(sf, filepath.Base(sf))
		fmt.Println("A signed copy of this executable was created locally :", filepath.Base(sf))
	}

}
