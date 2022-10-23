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
	"-e    encrypt\n\n"

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func getPassword(confirmPass bool) ([]byte, error) {

	state, err := term.GetState(int(os.Stdin.Fd()))
	checkError(err)

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

func encrypt(password []byte, inputFile, outputFile *string) {

	buff, err := os.ReadFile(*inputFile)
	checkError(err)

	buff, err = crypto.Encrypt(password, buff)
	checkError(err)

	err = os.WriteFile(*outputFile, buff, 0644)
	checkError(err)
}

func decrypt(password []byte, inputFile, outputFile *string) {

	buff, err := os.ReadFile(*inputFile)
	checkError(err)

	buff, err = crypto.Decrypt(password, buff)
	checkError(err)

	err = os.WriteFile(*outputFile, buff, 0644)
	checkError(err)
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
		log.Fatalf("Error: Input file not specified\n\n")
	}
	if outputFile = flag.Arg(1); outputFile == "" {
		log.Fatalf("Error: Output file not specified\n\n")
	}

	if flag.NFlag() > 1 {
		log.Fatalf("More than one option was passed\n\n")
	}

	password, err := getPassword(encFlag)
	if err != nil {
		log.Fatal(err)
	}

	switch {
	case encFlag:
		encrypt(password, &inputFile, &outputFile)
	default:
		decrypt(password, &inputFile, &outputFile)
	}
}
