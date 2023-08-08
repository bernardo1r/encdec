package encdec

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/crypto/argon2"

	"golang.org/x/term"
)

const KeySize = 32

func ReadPassword() ([]byte, error) {
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
	fmt.Print("Password: ")
	password, err := term.ReadPassword(stdin)
	fmt.Println("")
	if err != nil {
		return nil, err
	}
	return password, nil
}

func random(n uint8) ([]byte, error) {
	buff := make([]byte, n)
	_, err := rand.Read(buff)
	return buff, err
}

func Key(password []byte, params *Params) ([]byte, error) {
	err := params.Check()
	if err != nil {
		return nil, err
	}

	key := argon2.IDKey(
		password,
		params.Salt,
		params.ArgonTime,
		params.ArgonMemory,
		params.ArgonThreads,
		KeySize,
	)

	return key, nil
}

func NewKey(password []byte, params *Params) ([]byte, []byte, error) {
	err := params.Check()
	if err != nil {
		return nil, nil, err
	}

	salt, err := random(params.SaltSize)
	if err != nil {
		return nil, nil, fmt.Errorf("generating salt: %w", err)
	}
	params.Salt = salt
	key, _ := Key(password, params)

	return key, params.Salt, nil
}
