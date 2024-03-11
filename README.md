# integrity
Sign a binary or check it from inside the executable.

## How to use it


1. Build everything

````
task build

````
   
    
2. Create you binary, importing this package, an implementing signing validation process.

````

import github.com/xavier268/integrity

// Typical implementation of a signed binary

// Upon launch, read credentials from command line, then check it
if ! IsValid(credentials string) {
    panic("The provided credetials are invalid")
}

````

3. Use the "sign" tool to sign the built binary

````

$> sign.exe -p "credentials" "path/to/unsignadebinary" [ "path/to/signedbinary" ]

````

4. Use the signed and secured copy of the binary. 
   
    * The signed copy will only load with a valid credential
    * If a single byte of the binary is modified, it will refuse to run
    * The executable file can be renamed or moved freely
    * The credentials do not appear in clear in the binary code.
