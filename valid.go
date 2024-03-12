// include this package to verify binary access
package integrity

// include this package to be able to verify access can be granted.
import "github.com/xavier268/integrity/internal/lib"

const (
	VERSION   = lib.VERSION
	COPYRIGHT = lib.COPYRIGHT
)

// Should access be granted ?
func IsValid(credentials string) bool {
	return lib.IsValid(credentials, nil)
}
