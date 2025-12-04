package encdec

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/crypto/argon2"

	"golang.org/x/term"
)

const keySize = 32

func WithTerminal(f func(in *os.File, out *os.File) error) (err error) {
	if runtime.GOOS == "windows" {
		in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer func() {
			err2 := in.Close()
			err = errors.Join(err, err2)
		}()

		out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer func() {
			err2 := out.Close()
			err = errors.Join(err, err2)
		}()

		return f(in, out)
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		return f(tty, tty)
	}

	return errors.New("no terminal available")

}

func printfToTerminal(message string) error {
	err := WithTerminal(func(_ *os.File, out *os.File) error {
		_, err := fmt.Fprint(out, message)
		return err
	})
	return err
}

func readPasswordFromTerminal() ([]byte, error) {
	var password []byte
	err := WithTerminal(func(in *os.File, _ *os.File) error {
		var err error
		password, err = term.ReadPassword(int(in.Fd()))
		return err
	})
	return password, err
}

// ReadPassword reads the password from stdin without local echo,
// displaying message before reading the password.
// It is safe to interrupt the program with SIGINT when blocked
// by this function as it will restore the previous state of terminal on exit.
func ReadPassword(message string, repeat bool) ([]byte, error) {
	err := printfToTerminal(message)
	if err != nil {
		return nil, err
	}

	password, err := readPasswordFromTerminal()
	if err != nil {
		return nil, err
	}

	err = printfToTerminal("\n")
	if err != nil {
		return nil, err
	}
	if repeat {
		err := printfToTerminal(message)
		if err != nil {
			return nil, err
		}

		passwordCheck, err := readPasswordFromTerminal()
		if err != nil {
			return nil, err
		}

		err = printfToTerminal("\n")
		if err != nil {
			return nil, err
		}

		if subtle.ConstantTimeCompare(password, passwordCheck) == 0 {
			return nil, errors.New("password do not match")
		}
	}
	return password, nil
}

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
	err := params.checkFormatted()
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
