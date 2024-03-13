// include this package to control access to binary
package valid

// include this package to be able to verify access can be granted.
import (
	"fmt"

	"github.com/xavier268/integrity/internal/lib"

	_ "embed"
)

const (
	VERSION   = lib.VERSION
	COPYRIGHT = lib.COPYRIGHT
)

// The public key will be embedded into the binary
// The secret key, if it exists, is never imported
// when only importing the valid package.
//
//go:embed pub.der
var pubDer []byte

// Should access be granted ?
func IsValid(credentials string) bool {
	if len(pubDer) == 0 {
		fmt.Println("No public key found. Using hash without encryption.")
		pubDer = nil
	}

	return lib.IsValid(credentials, pubDer)
}
