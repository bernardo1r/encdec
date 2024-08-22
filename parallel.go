package encdec

import (
	"context"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sync/errgroup"
)

// Encrypt encrypts src into dst using a 256-bit key and the params.
func Encrypt(key []byte, src io.Reader, dst io.Writer, params *Params) error {
	if params == nil {
		return ErrNilParams
	}
	err := params.checkFormatted()
	if err != nil {
		return err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	err = process(src,
		int(params.ChunkSize),
		dst,
		int(params.ChunkSize)+aead.Overhead(),
		func(input []byte, output []byte) ([]byte, error) {
			ciphertext := aead.Seal(output[:0], nonce, input, nil)
			err := incNonce(nonce)
			return ciphertext, err
		},
	)
	if err != nil {
		return fmt.Errorf("ecryption: %w", err)
	}

	return nil
}

// Decrypt decrypts src into dst using a 256-bit key and the params.
func Decrypt(key []byte, src io.Reader, dst io.Writer, params *Params) error {
	if params == nil {
		return ErrNilParams
	}
	err := params.checkFormatted()
	if err != nil {
		return err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	err = process(
		src,
		int(params.ChunkSize)+aead.Overhead(),
		dst,
		int(params.ChunkSize),
		func(input []byte, output []byte) ([]byte, error) {
			plaintext, err := aead.Open(output[:0], nonce, input, nil)
			if err != nil {
				return nil, err
			}
			err = incNonce(nonce)
			return plaintext, err
		},
	)
	if err != nil {
		return fmt.Errorf("decryption: %w", err)
	}

	return nil
}

func process(src io.Reader, buffInSize int, dst io.Writer, buffOutSize int, p func(input []byte, output []byte) ([]byte, error)) error {
	buffIn := make([]byte, buffInSize)
	buffOut := make([]byte, buffOutSize)
	group, ctx := errgroup.WithContext(context.Background())
	chanIn := make(chan []byte)
	chanOut := make(chan []byte)
	read := make(chan struct{})
	written := make(chan struct{})
	group.Go(func() error {
		defer close(chanIn)
		for {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			n, err := src.Read(buffIn)
			switch {
			case errors.Is(err, io.EOF):
				return nil
			case err != nil:
				return err
			}
			chanIn <- buffIn[:n]
			<-read
		}
	})
	group.Go(func() error {
		defer close(chanOut)
		defer close(read)
		for input := range chanIn {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			output, err := p(input, buffOut)
			if err != nil {
				return err
			}
			read <- struct{}{}
			chanOut <- output
			<-written
		}
		return nil
	})
	group.Go(func() error {
		defer close(written)
		for output := range chanOut {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			_, err := dst.Write(output)
			if err != nil {
				return err
			}
			written <- struct{}{}
		}
		return nil
	})
	err := group.Wait()
	if err != ctx.Err() {
		return err
	}

	return nil
}
