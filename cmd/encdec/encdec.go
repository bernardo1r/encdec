package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/bernardo1r/encdec"
)

const usage = "Usage: encdec [options...] [INPUT_FILE] [OUTPUT_FILE]\n" +
	"Default option is to decrypt\n\n" +
	"Options:\n\n" +
	"    -p    password, if not provided will be prompted\n" +
	"    -d    decrypt\n" +
	"    -e    encrypt\n"

const passwordMessage = "Password: "

func checkError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func checkCloseError(err error, file *os.File) {
	if err != nil {
		file.Close()
		os.Remove(file.Name())
		log.Fatalln(err)
	}
}

func openFiles(inputFile string, outputFile string) (*os.File, *os.File, error) {
	src, err := os.Open(inputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("input file: %w", err)
	}

	dst, err := os.Create(outputFile)
	if err != nil {
		src.Close()
		return nil, nil, fmt.Errorf("output file: %w", err)
	}

	return src, dst, nil
}

func encrypt(password []byte, inputFile string, outputFile string) {
	src, dst, err := openFiles(inputFile, outputFile)
	checkError(err)
	defer src.Close()
	defer dst.Close()

	var params encdec.Params
	key, err := encdec.Key(password, &params)
	checkCloseError(err, dst)

	header, err := params.MarshalHeader()
	checkCloseError(err, dst)

	_, err = dst.Write(header)
	checkCloseError(err, dst)

	err = encdec.Encrypt(key, src, dst, &params)
	checkCloseError(err, dst)

	checkCloseError(err, dst)
}

func decrypt(password []byte, inputFile string, outputFile string) {
	src, dst, err := openFiles(inputFile, outputFile)
	checkError(err)
	defer src.Close()
	defer dst.Close()

	params, err := encdec.ParseHeader(src)
	checkCloseError(err, dst)

	key, err := encdec.Key(password, params)
	checkCloseError(err, dst)

	err = encdec.Decrypt(key, src, dst, params)
	checkCloseError(err, dst)
}

func main() {
	log.SetFlags(0)

	if len(os.Args) == 1 {
		log.Fatalf("%s", usage)
	}
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s", usage) }

	var decFlag, encFlag bool
	var pass string
	flag.StringVar(&pass, "p", "", "encryption password")
	flag.BoolVar(&decFlag, "d", false, "encrypt the input")
	flag.BoolVar(&encFlag, "e", false, "decrypt the input")
	flag.Parse()

	if decFlag && encFlag {
		log.Fatalf("More than one option was passed\n")
	}

	var inputFile, outputFile string
	if inputFile = flag.Arg(0); inputFile == "" {
		log.Fatalf("Error: Input file not specified\n")
	}
	if outputFile = flag.Arg(1); outputFile == "" {
		log.Fatalf("Error: Output file not specified\n")
	}

	var password []byte
	var err error
	if pass != "" {
		password = []byte(pass)
	} else {
		password, err = encdec.ReadPassword(passwordMessage)
		checkError(err)
	}

	switch {
	case encFlag:
		encrypt(password, inputFile, outputFile)
	default:
		decrypt(password, inputFile, outputFile)
	}
}
