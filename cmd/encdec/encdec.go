package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"

	"github.com/bernardo1r/encdec"
)

var Version string

const usage = "Usage: encdec [options...] [INPUT_FILE] [OUTPUT_FILE]\n" +
	"Default option is to decrypt\n\n" +
	"Options:\n\n" +
	"    -v    diplay version number\n" +
	"    -p    password, if not provided will be prompted\n" +
	"    -d    decrypt\n" +
	"    -e    encrypt\n"

const passwordMessage = "Password: "

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

func encrypt(password []byte, inputFile string, outputFile string) (err error) {
	src, dst, err := openFiles(inputFile, outputFile)
	if err != nil {
		return err
	}

	defer func() {
		err2 := src.Close()
		if err2 != nil && err == nil {
			err = err2
		}

		err2 = dst.Close()
		if err2 != nil && err == nil {
			err = err2
		}

		if err != nil {
			os.Remove(outputFile)
		}
	}()

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
		if err2 != nil && err == nil {
			err = err2
		}
	}()

	_, err = io.Copy(writer, src)
	return err
}

func decrypt(password []byte, inputFile string, outputFile string) (err error) {
	src, dst, err := openFiles(inputFile, outputFile)
	if err != nil {
		return err
	}

	defer func() {
		err2 := src.Close()
		if err2 != nil && err == nil {
			err = err2
		}

		err2 = dst.Close()
		if err2 != nil && err == nil {
			err = err2
		}

		if err != nil {
			os.Remove(outputFile)
		}
	}()

	params, err := encdec.ParseHeader(src)
	if err != nil {
		return err
	}

	key, err := encdec.Key(password, params)
	if err != nil {
		return err
	}

	reader, err := encdec.NewReader(key, src, params)
	if err != nil {
		return err
	}

	_, err = io.Copy(dst, reader)
	return err
}

func main() {
	log.SetFlags(0)

	if len(os.Args) == 1 {
		log.Fatalf("%s", usage)
	}
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s", usage) }

	var versionFlag, decFlag, encFlag bool
	var pass string
	flag.BoolVar(&versionFlag, "v", false, "display version number")
	flag.StringVar(&pass, "p", "", "encryption password")
	flag.BoolVar(&decFlag, "d", false, "encrypt the input")
	flag.BoolVar(&encFlag, "e", false, "decrypt the input")
	flag.Parse()

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
		log.Fatalln("more than one option was passed")
	}

	var inputFile, outputFile string
	if inputFile = flag.Arg(0); inputFile == "" {
		log.Fatalln("input file not specified")
	}
	if outputFile = flag.Arg(1); outputFile == "" {
		log.Fatalln("output file not specified")
	}

	var password []byte
	var err error
	if pass != "" {
		password = []byte(pass)
	} else {
		if encFlag {
			password, err = encdec.ReadPassword(passwordMessage, true)
		} else {
			password, err = encdec.ReadPassword(passwordMessage, false)
		}
		if err != nil {
			log.Fatalf("failed to read password: %v\n", err)
		}
	}

	if len(password) == 0 {
		log.Fatalln("password not provided")
	}

	switch {
	case encFlag:
		err = encrypt(password, inputFile, outputFile)
		if err != nil {
			err = fmt.Errorf("failed to encrypt: %w", err)
		}
	default:
		err = decrypt(password, inputFile, outputFile)
		if err != nil {
			err = fmt.Errorf("failed to decrypt: %w", err)
		}
	}

	if err != nil {
		log.Fatalln(err)
	}
}
