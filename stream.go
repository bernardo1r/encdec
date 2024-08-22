package encdec

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Writer writes to underlying writer encrypting the data.
type Writer struct {
	aead      cipher.AEAD
	chunkSize int64
	dst       io.Writer
	nonce     [chacha20poly1305.NonceSize]byte
	buff      bytes.Buffer
	err       error
}

// NewWriter creates a new Writer using a 256-bit key.
func NewWriter(key []byte, dst io.Writer, params *Params) (*Writer, error) {
	if params == nil {
		return nil, ErrNilParams
	}
	err := params.checkFormatted()
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	w := &Writer{
		aead:      aead,
		dst:       dst,
		chunkSize: params.ChunkSize,
	}
	w.buff.Grow(int(w.chunkSize + chacha20poly1305.Overhead))
	return w, nil
}

func (w *Writer) flush() error {
	ciphertext := w.aead.Seal(w.buff.Bytes()[:0], w.nonce[:], w.buff.Bytes(), nil)
	_, err := w.dst.Write(ciphertext)
	if err != nil {
		return err
	}
	w.buff.Reset()
	err = incNonce(w.nonce[:])
	return err
}

func min(x int, y int) int {
	if x < y {
		return x
	}
	return y
}

// Write writes len(p) bytes from p to the buffer.
// If the buffer is complete it will encrypt the data and
// write to the underlying writer with the AEAD tag appended to it.
// It returns the number of bytes written to the buffer and an error,
// if any.
func (w *Writer) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}

	total := len(p)
	for len(p) > 0 {
		size := min(int(w.chunkSize)-w.buff.Len(), len(p))
		n, _ := w.buff.Write(p[:size])
		p = p[n:]
		if w.buff.Len() == int(w.chunkSize) {
			err := w.flush()
			if err != nil {
				w.err = err
				return 0, w.err
			}
		}
	}
	return total, nil
}

// Close encrypt and write any remaning data in the buffer plus the AEAD tag,
// to the underlying writer. Close returns an error if it has already been called.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}

	w.err = w.flush()
	if w.err != nil {
		return w.err
	}

	w.err = errors.New("operation on closed writer")
	return nil
}

// Reader reads encrypted data from the underlying reader.
type Reader struct {
	aead      cipher.AEAD
	chunkSize int
	src       io.Reader
	nonce     [chacha20poly1305.NonceSize]byte
	buff      bytes.Buffer
	lastChunk bool
	err       error
}

// NewReader creates a new Reader using a 256-bit key.
func NewReader(key []byte, src io.Reader, params *Params) (*Reader, error) {
	if params == nil {
		return nil, ErrNilParams
	}
	err := params.checkFormatted()
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	r := &Reader{
		aead:      aead,
		src:       src,
		chunkSize: int(params.ChunkSize),
	}
	r.buff.Grow(r.chunkSize + chacha20poly1305.Overhead)
	return r, nil
}

// readChunk reads the next chunk from src and decrypt it.
// Returns true if it is the last chunk.
func (r *Reader) readChunk() (bool, error) {
	var last bool
	r.buff.Reset()
	n, err := io.CopyN(&r.buff, r.src, int64(r.chunkSize)+chacha20poly1305.Overhead)
	if err != nil {
		if err != io.EOF {
			return false, err
		}
		last = true
	}

	if n < (int64(r.chunkSize) + chacha20poly1305.Overhead) {
		last = true
	}

	plaintext, err := r.aead.Open(r.buff.Bytes()[:0], r.nonce[:], r.buff.Bytes(), nil)
	if err != nil {
		return false, err
	}
	r.buff.Truncate(len(plaintext))

	err = incNonce(r.nonce[:])
	if err != nil {
		return false, err
	}
	return last, nil
}

// Read up to len(p) bytes, decrypting they and storing them in p.
// It returns the number of bytes read and any error encountered.
// At the end of file, Read returns 0 and io.EOF.
func (r *Reader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	var total int
	for len(p) > 0 {
		if r.buff.Len() == 0 {
			if r.lastChunk {
				r.err = io.EOF
				if total == 0 {
					return 0, r.err
				}
				return total, nil
			}

			last, err := r.readChunk()
			if err != nil {
				r.err = err
				return 0, r.err
			}
			r.lastChunk = last
		}

		n, _ := r.buff.Read(p)
		total += n
		p = p[n:]
	}

	return total, nil
}
