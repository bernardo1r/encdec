package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"

	"github.com/bernardo1r/encdec"
	"golang.org/x/term"
)

var Version string

const usage = "Usage: encdec [options...] [INPUT_FILE]\n" +
	"Default option is to decrypt\n\n" +
	"Options:\n\n" +
	"    -v    diplay version number\n" +
	"    -p    password, if not provided will be prompted\n" +
	"    -d    decrypt\n" +
	"    -e    encrypt\n"

const passwordMessage = "Password: "

func encrypt(password []byte, src io.Reader, dst io.Writer) (err error) {
	var params encdec.Params
	key, err := encdec.Key(password, &params)
	if err != nil {
		return err
	}

	header, err := params.MarshalHeader()
	if err != nil {
		return err
	}

	_, err = dst.Write(header)
	if err != nil {
		return err
	}

	writer, err := encdec.NewWriter(key, dst, &params)
	if err != nil {
		return err
	}
	defer func() {
		err2 := writer.Close()
		err = errors.Join(err, err2)
	}()

	_, err = io.Copy(writer, src)
	return err
}

func decrypt(password []byte, src io.Reader, dst io.Writer) (err error) {
	buff := bufio.NewReader(src)
	params, err := encdec.ParseHeader(buff)
	if err != nil {
		return err
	}

	key, err := encdec.Key(password, params)
	if err != nil {
		return err
	}

	reader, err := encdec.NewReader(key, buff, params)
	if err != nil {
		return err
	}

	_, err = io.Copy(dst, reader)
	return err
}

func checkStdinRedirected() bool {
	return !term.IsTerminal(int(os.Stdin.Fd()))
}

func checkStdoutRedirected() bool {
	return !term.IsTerminal(int(os.Stdout.Fd()))
}

func encdecMain() (err error) {
	log.SetFlags(0)

	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	var (
		versionFlag, decFlag, encFlag, helpFlag bool
		passwordFlag                            string
	)
	flag.BoolVar(&helpFlag, "help", false, "display program usage")
	flag.BoolVar(&helpFlag, "h", false, "display program usage")
	flag.BoolVar(&versionFlag, "v", false, "display version number")
	flag.StringVar(&passwordFlag, "p", "", "encryption password")
	flag.BoolVar(&decFlag, "d", false, "decrypt the input")
	flag.BoolVar(&encFlag, "e", false, "encrypt the input")
	flag.Parse()

	if helpFlag {
		flag.Usage()
		return
	}

	if versionFlag {
		if Version != "" {
			fmt.Println(Version)
			return
		}

		info, ok := debug.ReadBuildInfo()
		if ok {
			fmt.Println(info.Main.Version)
			return
		}

		fmt.Println("(unknown)")
		return
	}

	if decFlag && encFlag {
		return errors.New("encryption and decryption options were passed")
	}

	inputFile := flag.Arg(0)
	okStdin := checkStdinRedirected()
	if okStdin && inputFile != "" {
		return errors.New("ambiguous input file provided from both stdin and file name")
	}
	if !okStdin && inputFile == "" {
		return errors.New("input file not provided from stdin or file name")
	}

	if !checkStdoutRedirected() {
		return errors.New("cowardly refusing to output to terminal")
	}

	var src *os.File
	if okStdin {
		src = os.Stdin
	} else {
		src, err = os.Open(inputFile)
		if err != nil {
			return fmt.Errorf("opening input file: %w", err)
		}
		defer func() {
			err2 := src.Close()
			err = errors.Join(err, err2)
		}()
	}

	dst := os.Stdout

	var password []byte
	if passwordFlag != "" {
		password = []byte(passwordFlag)
	} else {
		password, err = encdec.ReadPassword(passwordMessage, encFlag)
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}
	if len(password) == 0 {
		return errors.New("password not provided")
	}

	switch {
	case encFlag:
		err = encrypt(password, src, dst)
		if err != nil {
			return fmt.Errorf("failed to encrypt: %w", err)
		}
	default:
		err = decrypt(password, src, dst)
		if err != nil {
			return fmt.Errorf("failed to decrypt: %w", err)
		}
	}

	return nil
}

func main() {
	err := encdecMain()
	if err != nil {
		log.Fatalln(err)
	}
}
