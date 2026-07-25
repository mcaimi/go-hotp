# Simple HOTP Library written in Go

This is a simple HOTP library that implements the HOTP algorithm described in RFC4226.
The main HOTP function implements token generation following the rfc implementation (SHA-1 based HMAC) but the underlying HotpToken function can accept different HMAC functions.

## Usage

Simply import the library and use the preferred hashing function:

```Go
package main

import (
  "fmt"
  "encoding/hex"
  "github.com/mcaimi/go-hotp/rfc4226"
  )

const (
  KEY = "3132333435363738393031323334353637383930"
  INTERVAL = 0
  )

func main() {
  var token uint32

  key, err := hex.DecodeString(KEY);

  if err != nil {
    fmt.Println(err);
  } else {
    token = rfc4226.Hotp(key, INTERVAL, 6, "sha1");
    fmt.Printf("%d\n", token);
  }
}
```
