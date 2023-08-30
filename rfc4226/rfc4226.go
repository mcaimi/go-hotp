package rfc4226

// calculate HOTP tokens as per RFC4226
import (
  "math" 
  "encoding/binary"
  "github.com/mcaimi/go-hmac/rfc2104"
)

const (
  DBC_LEN = 4 // extract 4 bytes from the byte array during dynamic truncation
  VALID_TOKEN_LEN = 8
)

// the hmac object
type HOTP struct {
  key []byte;
  interval []byte;
  token_len int;
  hmac_algo string;
}

// generate a new hotp object
func NewHotp(key []byte, interval []byte, length int, algorithm string) HOTP {
  var x HOTP;

  // assign values
  x.key = key;
  x.interval = interval;
  x.token_len = length;
  x.hmac_algo = algorithm;

  // return hotp object
  return x;
}

// precompute all valid token lengths 
// these are modulo dividends (10**i) where 0<i<VALID_TOKEN_LEN
func moduloLenghts(max_token_len int) []uint32 {
  var modulos []uint32;

  modulos = make([]uint32, max_token_len);

  for i := 0; i < (max_token_len); i++ {
    modulos[i] = uint32(math.Pow(10, float64(i)));
  }

  return modulos;
}

// Dynamic Truncate
// Performs dynamic Truncation as described in RFC4226
//
// byteString: 20-bytes long HMAC hash, encoded as a byte array
//
func dT(byteString []byte) []byte {
  var offset uint32;
  var dbc []byte;

  // extract the 4 least significant bits from the last byte of the byteString
  offset = uint32(byteString[len(byteString) - 1] & 0x0f);

  // extract 4 bytes from byteString starting from offset
  dbc = byteString[offset:offset + DBC_LEN];

  // mask MSB, build value and return
  dbc[0] &= 0x7f;
  return dbc;
}

// Modulo function
// Performs modular division and returns an unsinged integer
//
// hmacPayload: 20-bytes long HMAC token
// token_len: length of the computed token
//
func modulo(hmacPayload []byte, token_len int) uint32 {
  var moduli []uint32;
  var hotpByte []byte;

  // precompute valid module lengths
  moduli = moduloLenghts(VALID_TOKEN_LEN);

  // perform dynamic truncation
  hotpByte = dT(hmacPayload);

  // convert and compute modulo
  // byte order is Big Endian
  return binary.BigEndian.Uint32(hotpByte) % uint32(moduli[token_len]);
}

// generic HOTP function
// 
// key: the secret key (byte array)
// interval: HOTP interval encoded as byte array
// 
func (t *HOTP) HotpToken() uint32 {
  var token uint32;

  token = modulo(rfc2104.Hmac(t.key, t.interval, t.hmac_algo), t.token_len);

  // return computed value
  return token;
}

