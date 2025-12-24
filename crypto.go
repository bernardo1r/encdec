package encdec

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

var (
	ErrNilParams = errors.New("params is nil")

	ErrArgonVersion = errors.New("invalid argon2 version")
	ErrArgonType = errors.New("invalid argon2 type")
	ErrSaltSize = errors.New("salt is not the same size as salt size")
	ErrSalt = errors.New("invalid salt size")
	ErrArgonTime = errors.New("invalid argon time")
	ErrArgonMemory = errors.New("invalid argon memory size")
	ErrArgonThreads = errors.New("invalid argon threads count")
	ErrChunkSize = errors.New("invalid chunk size")

	ErrParsing = errors.New("parsing header")
)

const keySize = 32

func incNonce(nonce []byte) error {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
		if i == 0 {
			return errors.New("chunk counter overflowed")
		}
	}
	return nil
}

func random(n uint8) ([]byte, error) {
	buff := make([]byte, n)
	_, err := rand.Read(buff)
	return buff, err
}

// Key uses argon2 algorithm to create a cryptographic key
// based on password and params.
//
// Depending on the parameters passed to argon2, it can take a significant
// amount of time and memory. Using the zero value of params it will use the
// first recommended parameters option specified in RFC9106.
func Key(password []byte, params *Params) ([]byte, error) {
	if params == nil {
		return nil, ErrNilParams
	}
	err := params.Check()
	if err != nil {
		return nil, err
	}

	if params.Salt == nil {
		salt, err := random(params.SaltSize)
		if err != nil {
			return nil, fmt.Errorf("generating salt: %w", err)
		}
		params.Salt = salt
	}

	key := argon2.IDKey(
		password,
		params.Salt,
		params.ArgonTime,
		params.ArgonMemory,
		params.ArgonThreads,
		keySize,
	)

	return key, nil
}
