package encdec_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/bernardo1r/encdec"
	"golang.org/x/crypto/chacha20poly1305"
)

func testRoundTrip(t *testing.T, params *encdec.Params, step int, length int) {
	src := make([]byte, length)
	_, err := rand.Read(src)
	if err != nil {
		t.Fatal(err)
	}

	key := make([]byte, chacha20poly1305.KeySize)
	_, err = rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	var buffer bytes.Buffer
	writer, err := encdec.NewWriter(key, &buffer, params)
	if err != nil {
		t.Fatal(err)
	}

	curr := src
	for len(curr) > 0 {
		b := len(curr)
		b = min(b, step)

		n, err := writer.Write(curr[:b])
		if err != nil {
			t.Fatal(err)
		}
		if b != n {
			t.Fatalf("writer return: expected: %v, got: %v", b, n)
		}

		curr = curr[b:]
	}

	err = writer.Close()
	if err != nil {
		t.Fatal(err)
	}

	reader, err := encdec.NewReader(key, &buffer, params)
	if err != nil {
		t.Fatal(err)
	}

	dst := make([]byte, step)
	for len(src) > 0 {
		n, err := reader.Read(dst)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(dst[:n], src[:n]) {
			t.Fatalf("wrong data")
		}

		src = src[n:]
	}

	_, err = reader.Read(dst)
	if err == nil {
		t.Fatalf("expected return error: io.EOF, got return error: nil")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected return error: io.EOF, got return error: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	params := encdec.NewParams()

	steps := []int{
		chacha20poly1305.Overhead + 1,
		100,
		int(params.ChunkSize),
		int(params.ChunkSize) + chacha20poly1305.Overhead,
		int(params.ChunkSize) + chacha20poly1305.Overhead + 1,
	}

	lengths := []int{
		0,
		steps[0] + 100,
		steps[1],
		steps[2] + 133,
		steps[3] + 100,
		steps[4] + 300,
	}

	for _, step := range steps {
		for _, length := range lengths {
			t.Run(fmt.Sprintf("step=%v,length=%v", step, length), func(t *testing.T) {
				t.Parallel()
				testRoundTrip(t, params, step, length)
			})
		}
	}
}
