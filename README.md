# integrity

[![Go Reference](https://pkg.go.dev/badge/github.com/xavier268/integrity.svg)](https://pkg.go.dev/github.com/xavier268/integrity) [![Go Report Card](https://goreportcard.com/badge/github.com/xavier268/integrity)](https://goreportcard.com/report/github.com/xavier268/integrity)

Sign a binary or validate if it should run.

## How to use it


### Build the signing tool

```bash
task build

```
   
### Create you binary as usual, importing this package, an validating the provided credential

For instance, main could start like this :

```go


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

    	// read password from command line
	flag.Parse()

    	// validate credentials
	if !integrity.IsValid(passw) { 
		fmt.Println("Access is denied")
		return
	}

	// Access is granted !
	fmt.Println("Access IS granted")
	// ... do things ...

}


```

### Use the "sign" tool to sign the built binary

**Caution** : I would make sens to include the signing process into your build pipeline.
Without a correct credential setup, the executable will refuse to launch.

```bash

sign.exe [ -p "credentials" -o "path/to/signedoutputbinary" ]  "path/to/unsignadebinary" 

```

**Note** : it is ok to set the output filename to the input filename to modify executable in place.

### Use the signed and secured copy of the binary. 
   
    * The signed copy will only load with a valid credential
    * If a single byte of the binary is modified, added or removed, it will refuse to run
    * The signed executable file can be renamed or moved freely
    * Obviously, no credentials can be extracted from the binary code.


# TODO

Think about the API to generate/use the private/public keypairs needed ?
* have a task to generate them as separate files that can be embedded as values in Sign (private key) and Integrity (public key) ?
* generate them in a separate directy (internal) - embed this dir as a FS and check if the key files are available or not ?
* hide visibility of keys outside lib ?