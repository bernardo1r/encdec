package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"github.com/bernardo1r/encdec/crypto"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"os"
	"os/signal"
)

const usage = "Usage: encdec [option] input_file output_file\n" +
	"Default option is to decrypt\n\n" +
	"Options:\n\n" +
	"-d    decrypt\n" +
	"-e    encrypt\n\n"

func getPassword(confirmPass bool) ([]byte, error) {

	state, err := terminal.GetState(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal(err)
	}

	c := make(chan os.Signal, 1)
	defer close(c)

	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		_, ok := <-c
		if ok {
			terminal.Restore(int(os.Stdin.Fd()), state)
			os.Exit(1)
		}
	}()

	fmt.Printf("Password: ")
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	fmt.Println("")

	if confirmPass {
		fmt.Printf("Confirm password: ")
		passwordConf, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Println("")

		if bytes.Compare(password, passwordConf) != 0 {
			return nil, errors.New("Passwords do not match")
		}
	}

	return password, nil
}

func encrypt(password []byte, inputFile, outputFile *string) error {

	buff, err := os.ReadFile(*inputFile)
	if err != nil {
		return err
	}

	buff, err = crypto.Encrypt(password, buff)
	if err != nil {
		return err
	}

	err = os.WriteFile(*outputFile, buff, 0644)
	if err != nil {
		return err
	}

	return nil
}

func decrypt(password []byte, inputFile, outputFile *string) error {

	buff, err := os.ReadFile(*inputFile)
	if err != nil {
		return err
	}

	buff, err = crypto.Decrypt(password, buff)
	if err != nil {
		return err
	}

	err = os.WriteFile(*outputFile, buff, 0644)
	if err != nil {
		return err
	}

	return nil

}

func main() {

	if len(os.Args) == 1 {
		log.Fatalf("%s", usage)
	}
	log.SetFlags(0)
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
		os.Exit(1)
	}

	switch {
	case encFlag:
		err = encrypt(password, &inputFile, &outputFile)
	default:
		err = decrypt(password, &inputFile, &outputFile)
	}

	if err != nil {
		log.Fatal(err)
	}
}
