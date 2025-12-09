package tui

import (
	"errors"
	"os"
	"runtime"
)

type TTY struct {
	in      *os.File
	out     *os.File
	generic bool
}

func NewTTY() (*TTY, error) {
	var (
		tty TTY
		err error
	)
	if runtime.GOOS == "windows" {
		tty.in, err = os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}

		tty.out, err = os.OpenFile("CONOUT$", os.O_RDWR, 0)
		if err != nil {
			return nil, errors.Join(err, tty.in.Close())
		}
		return &tty, nil
	}

	tty.in, err = os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("no terminal available")
	}
	tty.generic = true
	return &tty, nil
}

func (tty *TTY) In() *os.File {
	return tty.in
}

func (tty *TTY) Out() *os.File {
	if tty.generic {
		return tty.in
	}
	return tty.out
}

func (tty *TTY) Close() error {
	err := tty.in.Close()
	var err2 error
	if !tty.generic {
		err2 = tty.out.Close()
	}
	return errors.Join(err, err2)
}
