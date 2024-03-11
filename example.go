package main

import (
	"fmt"
	"os"

	"github.com/xavier268/integrity/util"
)

func main() {

	fmt.Println("Hello Word")
	fmt.Println(os.Args[0])
	fmt.Println("This executable will be signed")
	if util.IsValid() {
		fmt.Println("This executable is correctly signed")
	} else {
		util.Sign()
		fmt.Println("A signed copy of this executable was created")
	}

}
