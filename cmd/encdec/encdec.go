package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/bernardo1r/encdec"
)

const usage = "Usage: encdec [option] input_file output_file\n" +
	"Default option is to decrypt\n\n" +
	"Options:\n\n" +
	"-d    decrypt\n" +
	"-e    encrypt\n"

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
		return nil, nil, fmt.Errorf("opening input file: %w", err)
	}

	dst, err := os.Create(outputFile)
	if err != nil {
		src.Close()
		return nil, nil, fmt.Errorf("opening output file: %w", err)
	}

	return src, dst, nil
}

func encrypt(password []byte, inputFile string, outputFile string) {
	src, dst, err := openFiles(inputFile, outputFile)
	checkError(err)
	defer src.Close()
	defer dst.Close()

	var params encdec.Params
	key, _, err := encdec.NewKey(password, &params)
	checkCloseError(err, dst)

	header, err := params.MarshalHeader()
	checkCloseError(err, dst)

	_, err = dst.Write(header)
	checkCloseError(err, dst)

	w, err := encdec.NewWriter(key, dst, &params)
	checkCloseError(err, dst)

	_, err = io.Copy(w, src)
	checkCloseError(err, dst)

	err = w.Close()
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

	r, err := encdec.NewReader(key, src, params)
	checkCloseError(err, dst)

	_, err = io.Copy(dst, r)
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

	password, err := encdec.ReadPassword()
	checkError(err)

	switch {
	case encFlag:
		encrypt(password, inputFile, outputFile)
	default:
		decrypt(password, inputFile, outputFile)
	}
}
