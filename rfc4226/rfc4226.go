package rfc4226

// calculate HOTP tokens as per RFC4226
import (
  "math" 
  "encoding/binary"
)

const (
  DBC_LEN = 4 // extract 4 bytes from the byte array during dynamic truncation
  VALID_TOKEN_LEN = 8
)

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
func DT(byteString []byte) []byte {
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
func Modulo(hmacPayload []byte, token_len int) uint32 {
  var moduli []uint32;
  var hotpByte []byte;

  // precompute valid module lengths
  moduli = moduloLenghts(VALID_TOKEN_LEN);

  // perform dynamic truncation
  hotpByte = DT(hmacPayload);

  // convert and compute modulo
  // byte order is Big Endian
  return binary.BigEndian.Uint32(hotpByte) % uint32(moduli[token_len]);
}

// generic HOTP function
// 
// key: the secret key (byte array)
// interval: HOTP interval encoded as byte array
// 
func HotpToken(key []byte, interval []byte, token_len int, hmac_func func([]byte, []byte) []byte) uint32 {
  var token uint32;

  token = Modulo(hmac_func(key, interval), token_len);

  // return computed value
  return token;
}

