# integrity

[![Go Reference](https://pkg.go.dev/badge/github.com/xavier268/integrity.svg)](https://pkg.go.dev/github.com/xavier268/integrity) [![Go Report Card](https://goreportcard.com/badge/github.com/xavier268/integrity)](https://goreportcard.com/report/github.com/xavier268/integrity)

Sign a binary or validate if it should run.

## How to use it

````bash
$> task
task: [default] task --list-all
task: Available tasks for this project:
* build:          build sign utility
* clean:          clean caches and binaries, and test dirs
* default:        default task will display task menu
* example:        run example
* generate:       generate a new key pair
* godoc:          launch godoc viewer and open browser page on windows
* test:           run tests

````

   
## To create a signed and controlled application


### (Re)genarate a key pair

```bash
$> task generate
```
This Task will generate a key pair, and build the signing tool and run tests.

### Create your signable app 

Just create any app, but make sure it imports the 'valid' package.
Then, you can grant access by providing the credential that was used to sign.

Example :

```go
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
	// The ID of the key is available to check consistency when signing.
	fmt.Println("Validating with key :", valid.KeyID())
	if !valid.IsValid(passw) { // validate credentials
		fmt.Println("Access is DENIED")
		return
	}
	// Access is granted !
	fmt.Println("Access is GRANTED")
	// ... do things ...
```

### Use the "sign" tool to sign the built binary

**Caution** : It would make sense to include the signing process into your build pipeline.
Without a correct credential setup, the executable will refuse to launch.

Example :

```bash
$> sign.exe  -p "mypassword" -o "path/to/myapp/signed-binary"   "path/to/myapp/binary" 

```

**Notes** : 
* You may set the output filename to the input filename if you so wish.
* You may sign an already signed binary with new credentials and/or new key and it will work.
* If no keypair is defined, signing will just use a hash. Less secure, same functionnality.

### Using the signed and secured copy of your app
   
* The signed copy will only load with a valid credential
* If a single byte of the binary is modified, added or removed, it will refuse to run
* The signed executable file can be renamed or moved freely
* Obviously, no credentials can be extracted from the binary code.

