package encdec

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/bernardo1r/encdec/internal/test/utils"
)

func TestRandom(t *testing.T) {
	t.Parallel()
	size := 255
	buff, err := random(uint8(size))
	if err != nil {
		t.Fatal(err)
	}

	if len(buff) != size {
		t.Fatal("buffer " + utils.SerrorDiff(size, len(buff)))
	}
}

func TestIncNonce(t *testing.T) {
	t.Parallel()
	nonces := []struct {
		in []byte
		expected []byte
		err bool
	}{
		{
			[]byte{0x00},
			[]byte{0x01},
			false,
		},
		{
			[]byte{0xfe},
			[]byte{0xff},
			false,
		},
		{
			[]byte{0xff},
			nil,
			true,
		},
		{
			[]byte{0x00, 0x00},
			[]byte{0x00, 0x01},
			false,
		},
		{
			[]byte{0x00, 0xfe},
			[]byte{0x00, 0xff},
			false,
		},
		{
			[]byte{0x00, 0xff},
			[]byte{0x01, 0x00},
			false,
		},
		{
			[]byte{0xff, 0xff},
			nil,
			true,
		},
	}

	for idx, nonce := range nonces {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			t.Parallel()

			err := incNonce(nonce.in)
			if err == nil {
				if !bytes.Equal(nonce.expected, nonce.in) {
					t.Fatalf("expected: %v, got: %v", nonce.expected, nonce.in)
				} else {
					return
				}
			}

			if !nonce.err {
				t.Fatalf("expected return: nil, got return: %v", err)
			}

		})
	}
}

