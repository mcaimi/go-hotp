package rfc4226

import (
  "fmt"
  "testing"
  "encoding/binary"
  "encoding/hex"
)

// test vectors as described here: https://www.rfc-editor.org/rfc/rfc4226
const SECRET string = "3132333435363738393031323334353637383930"

type HOTPTest struct {
  interval uint64
  result string
}

var TestVectors = []HOTPTest {
  HOTPTest{0, "755224"},
  HOTPTest{1, "287082"},
  HOTPTest{2, "359152"},
  HOTPTest{3, "969429"},
  HOTPTest{4, "338314"},
  HOTPTest{5, "254676"},
  HOTPTest{6, "287922"},
  HOTPTest{7, "162583"},
  HOTPTest{8, "399871"},
  HOTPTest{9, "520489"},
}

func TestHotp(t *testing.T) {
  secretBytes, err := hex.DecodeString(SECRET);
  if err != nil {
    t.Errorf("Error [%q]\n", err);
  } 

  t.Logf("SECRET: %q\n", secretBytes);

  for i := range TestVectors {
    i_bytes := make([]byte, 8);
    binary.BigEndian.PutUint64(i_bytes, TestVectors[i].interval);
    h := NewHotp(secretBytes, i_bytes, 6, "sha1");
    v := fmt.Sprintf("%d", h.HotpToken());
    t.Logf("HOTP Value: %q, Reference: %q\n", v, TestVectors[i].result);

    if v != TestVectors[i].result {
      t.Fail();
    }
  }
}

