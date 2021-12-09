package crypto

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/argon2"
	chacha "golang.org/x/crypto/chacha20poly1305"
)

const (
	KeyLen = 32

	SaltLen = 16

    NonceSize = 24

	ArgonITime = 3

	ArgonMemory = 1 << 20

	ArgonThreads = 8
)

func makeIKey(password, salt []byte) ([]byte) {

	return argon2.Key(password, salt, ArgonITime, ArgonMemory, ArgonThreads, KeyLen)
}

func Encrypt(password string, plaintext []byte) ([]byte, error) {

	if len(password) == 0 {
		return nil, errors.New("Password too short")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("Plaintext too short")
	}

	salt := make([]byte, SaltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	passByte := []byte(password)
    key := makeIKey(passByte, salt)

	aead, err := chacha.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, SaltLen+NonceSize, SaltLen+NonceSize+len(plaintext)+aead.Overhead())
	copy(nonce, salt)

	_, err = rand.Read(nonce[SaltLen:])
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nonce, nonce[SaltLen:], plaintext, nil)

	return ciphertext, nil
}

func Decrypt(password string, ciphertext []byte) ([]byte, error) {
    if len(password) == 0 {
        return nil, errors.New("Password too short")
    }
    if len(ciphertext) < (SaltLen + NonceSize) {
        return nil, errors.New("Ciphertext too short")
    }

    salt, nonce, ciphertext := ciphertext[:SaltLen], ciphertext[SaltLen:SaltLen+NonceSize], ciphertext[SaltLen+NonceSize:]

    passByte := []byte(password)
    key := makeIKey(passByte, salt)

    aead, err := chacha.NewX(key)
    if err != nil {
        return nil, err
    }

    plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}
