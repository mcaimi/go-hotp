package rfc4226

// compute HOTP tokens as per RFC4226
import (
  "encoding/binary"
)

// computes an HOTP token with SHA-1 as the HMAC hashing algotithm
// this is standard RFC implementation
func Hotp(key []byte, interval uint64, token_len int, algorithm string) uint32 {
  var interval_bytes []byte;

  // compute HOTP digest
  // interval is by convention a big-endian encoded 64 bit integer
  interval_bytes = make([]byte, 8);
  binary.BigEndian.PutUint64(interval_bytes, interval);

  var h HOTP;
  h = NewHotp(key, interval_bytes, token_len, algorithm);

  // compute token value as per RFC
  return h.HotpToken();
}
