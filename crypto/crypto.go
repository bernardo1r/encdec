	package crypto

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/bernardo1r/encdec/argon2"
)

const NonceSize = 12

var CipherNonce = bytes.Repeat([]byte{0}, NonceSize)

const HeaderDelim = '\n'

func marshalHeader(key *argon2.ArgonKey) ([]byte, error) {

	header, err := key.Marshal()
	if err != nil {
		return nil, fmt.Errorf("could not marshal header: %w", err)
	}
	return append(header, HeaderDelim), nil
}

func Encrypt(password []byte, src io.Reader, dst io.Writer) error {
	argonKey, err := argon2.NewArgonKey(password)
	if err != nil {
		return err
	}

	header, err := marshalHeader(argonKey)
	if err != nil {
		return err
	}

	writer, err := NewWriter(argonKey.Key(), header, dst)
	if err != nil {
		return err
	}

	n, err := io.Copy(writer, src)
	if err != nil {
		return err
	}
	if n == 0 {
		fmt.Println("Encrypted empty file!")
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	return nil
}

func parseHeader(src io.ReadSeeker) ([]byte, error) {
	reader := bufio.NewReader(src)
	header, err := reader.ReadBytes(HeaderDelim)
	header = header[:len(header)-1]
	switch {
	case err != nil:
		return nil, err
	case len(header) == 0:
		return nil, errors.New("empty header")
	}
	_, err = src.Seek(int64(-reader.Buffered()), 1)
	if err != nil {
		return nil, err
	}

	return header, nil
}

func Decrypt(password []byte, src io.ReadSeeker, dst io.Writer) error {
	if len(password) == 0 {
		return errors.New("password too short")
	}

	header, err := parseHeader(src)
	if err != nil {
		return err
	}

	argonKey, err := argon2.NewArgonKey(password)
	if err != nil {
		return err
	}

	err = argonKey.ParseHeader(header)
	if err != nil {
		return err
	}

	reader, err := NewReader(argonKey.Key(), src)
	if err != nil {
		return err
	}

	n, err := io.Copy(dst, reader)
	if err != nil {
		return err
	}
	if n == 0 {
		fmt.Println("Decrypted empty file!")
	}

	return nil
}
