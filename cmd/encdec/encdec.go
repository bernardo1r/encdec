package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/bernardo1r/encdec/crypto"
	"golang.org/x/term"
)

const usage = "Usage: encdec [option] input_file output_file\n" +
	"Default option is to decrypt\n\n" +
	"Options:\n\n" +
	"-d    decrypt\n" +
	"-e    encrypt\n"

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func checkCloseError(err error, file *os.File) {
	if err != nil {
		file.Close()
		os.Remove(file.Name())
		log.Fatal(err)
	}
}

func getPassword(confirmPass bool) ([]byte, error) {
	state, err := term.GetState(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}

	c := make(chan os.Signal, 1)
	defer close(c)

	signal.Notify(c, os.Interrupt)
	go func() {
		_, ok := <-c
		if ok {
			term.Restore(int(os.Stdin.Fd()), state)
			os.Exit(1)
		}
	}()

	fmt.Printf("Password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	fmt.Println("")

	if confirmPass {
		fmt.Printf("Confirm password: ")
		passwordConf, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Println("")

		if !bytes.Equal(password, passwordConf) {
			return nil, errors.New("passwords do not match")
		}
	}

	return password, nil
}

func openFiles(inputFile string, outputFile string) (*os.File, *os.File, error) {
	src, err := os.Open(inputFile)
	if err != nil {
		return nil, nil, err
	}

	dst, err := os.Create(outputFile)
	if err != nil {
		src.Close()
		return nil, nil, err
	}

	return src, dst, nil
}

func encrypt(password []byte, inputFile, outputFile string) {
	src, dst, err := openFiles(inputFile, outputFile)
	checkError(err)
	defer src.Close()
	defer dst.Close()

	err = crypto.Encrypt(password, src, dst)
	checkCloseError(err, dst)
}

func decrypt(password []byte, inputFile string, outputFile string) {
	src, dst, err := openFiles(inputFile, outputFile)
	checkError(err)
	defer src.Close()
	defer dst.Close()

	err = crypto.Decrypt(password, src, dst)
	checkCloseError(err, dst)
}

func main() {
	log.SetFlags(0)

	if len(os.Args) == 1 {
		log.Fatalf("%s", usage)
	}
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s", usage) }

	var decFlag, encFlag bool
	flag.BoolVar(&decFlag, "d", false, "encrypt the input")
	flag.BoolVar(&encFlag, "e", false, "decrypt the input")
	flag.Parse()

	var inputFile, outputFile string

	if inputFile = flag.Arg(0); inputFile == "" {
		log.Fatalf("Error: Input file not specified\n")
	}
	if outputFile = flag.Arg(1); outputFile == "" {
		log.Fatalf("Error: Output file not specified\n")
	}

	if flag.NFlag() > 1 {
		log.Fatalf("More than one option was passed\n")
	}

	password, err := getPassword(encFlag)
	checkError(err)

	switch {
	case encFlag:
		encrypt(password, inputFile, outputFile)
	default:
		decrypt(password, inputFile, outputFile)
	}
}
