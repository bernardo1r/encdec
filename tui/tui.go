package tui

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/bernardo1r/encdec/internal/tui"
	"golang.org/x/term"
)

// ReadPassword reads the password from tty without local echo,
// displaying message before reading the password.
func ReadPassword(message string, repeat bool) ([]byte, error) {
	tty, err := tui.NewTTY()
	if err != nil {
		return nil, err
	}

	_, err = fmt.Fprint(tty.Out(), message)
	if err != nil {
		return nil, err
	}

	password, err := term.ReadPassword(int(tty.In().Fd()))
	if err != nil {
		return nil, err
	}

	_, err = fmt.Fprint(tty.Out(), "\n")
	if err != nil {
		return nil, err
	}
	if repeat {
		_, err = fmt.Fprint(tty.Out(), message)
		if err != nil {
			return nil, err
		}

		passwordCheck, err := term.ReadPassword(int(tty.In().Fd()))
		if err != nil {
			return nil, err
		}

		_, err = fmt.Fprint(tty.Out(), "\n")
		if err != nil {
			return nil, err
		}

		if subtle.ConstantTimeCompare(password, passwordCheck) == 0 {
			return nil, errors.New("password do not match")
		}
	}
	return password, nil
}
