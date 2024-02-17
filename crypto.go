package encdec

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/crypto/argon2"

	"golang.org/x/term"
)

const keySize = 32

// ReadPassword reads the password from stdin without local echo,
// displaying message before reading the password.
// It is safe to interrupt the program with SIGINT when blocked
// by this function as it will restore the previous state of terminal on exit.
func ReadPassword(message string) ([]byte, error) {
	passwordCtx, passwordCancel := context.WithCancel(context.Background())
	defer passwordCancel()
	stdin := int(os.Stdin.Fd())
	state, err := term.GetState(stdin)
	if err != nil {
		return nil, err
	}

	signalCtx, signalCancel := signal.NotifyContext(passwordCtx, os.Interrupt)
	go func() {
		<-signalCtx.Done()
		signalCancel()
		if passwordCtx.Err() != nil {
			return
		}
		term.Restore(stdin, state)
		passwordCancel()
		fmt.Println("")
		os.Exit(1)
	}()
	fmt.Print(message)
	password, err := term.ReadPassword(stdin)
	fmt.Println("")
	if err != nil {
		return nil, err
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
		return nil, errors.New("")
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
