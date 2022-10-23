package crypto

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/bernardo1r/encdec/argon2"
	chacha "golang.org/x/crypto/chacha20poly1305"
)

const NonceSize = 12

var CipherNonce = bytes.Repeat([]byte{0}, NonceSize)

var HeaderDelim = []byte("\n")

func marshalHeader(key *argon2.ArgonKey) ([]byte, error) {

	header, err := key.Marshal()
	if err != nil {
		return nil, fmt.Errorf("could not marshal header: %w", err)
	}
	return append(header, HeaderDelim...), nil
}

func Encrypt(password, plaintext []byte) ([]byte, error) {

	if len(plaintext) == 0 {
		return nil, errors.New("plaintext too short")
	}

	argonKey, err := argon2.NewArgonKey(password)
	if err != nil {
		return nil, err
	}

	aead, err := chacha.New(argonKey.Key())
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, CipherNonce, plaintext, nil)

	header, err := marshalHeader(argonKey)
	if err != nil {
		return nil, err
	}

	return append(header, ciphertext...), nil
}

func parseHeader(ciphertext []byte) ([]byte, []byte, error) {

	header, ciphertext, found := bytes.Cut(ciphertext, HeaderDelim)
	if len(header) == 0 || !found {
		return nil, nil, errors.New("could not find header")
	}

	return header, ciphertext, nil
}

func Decrypt(password, ciphertext []byte) ([]byte, error) {

	if len(password) == 0 {
		return nil, errors.New("password too short")
	}

	header, ciphertext, err := parseHeader(ciphertext)
	if err != nil {
		return nil, err
	}

	argonKey, err := argon2.NewArgonKey(password)
	if err != nil {
		return nil, err
	}

	err = argonKey.ParseHeader(header)
	if err != nil {
		return nil, err
	}

	aead, err := chacha.New(argonKey.Key())
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, CipherNonce, ciphertext, nil)
	if err != nil {
		//wrap it or not?
		return nil, fmt.Errorf("could not decrypt and authenticate: %w", err)
	}

	return plaintext, nil
}
