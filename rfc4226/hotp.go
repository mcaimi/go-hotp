package rfc4226

// compute HOTP tokens as per RFC4226
import (
  "encoding/binary"
  "github.com/mcaimi/go-hmac/rfc2104"
)

// computes an HOTP token with SHA-1 as the HMAC hashing algotithm
// this is standard RFC implementation
func HOTP(key []byte, interval uint64, token_len int) uint32 {
  var interval_bytes []byte;

  // compute HOTP digest
  // interval is by convention a big-endian encoded 64 bit integer
  interval_bytes = make([]byte, 8);
  binary.BigEndian.PutUint64(interval_bytes, interval);
  // compute token value as per RFC (using SHA-1 as hashing algorithm)
  return HotpToken(key, interval_bytes, token_len, rfc2104.SHA1Hmac);
}
