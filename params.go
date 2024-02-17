package encdec

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Default values of params fields.
const (
	ArgonVersion = 19
	ArgonType    = "argon2id"
	SaltSize     = 16
	ArgonTime    = 1
	ArgonMemory  = 1 << 21
	ArgonThreads = 4
	ChunkSize    = 64 * (1 << 10) // 64 KiB
)

// Params represents the parameters used to generate a symmetric key using
// Argon2 and the chunk size in bytes for splitting the payload before
// encrypting they with unique nonces.
type Params struct {
	// ArgonVersion defines what version number of Argon2
	// will be used to derivate the key.
	ArgonVersion uint8

	// ArgonType is the version of Argon2 that will be used
	// to derivate the key.
	ArgonType string

	// SaltSize is the length, in bytes, of the salt that will be
	// generated.
	SaltSize uint8

	// Salt is the actual salt used.
	Salt []byte

	// ArgonTime is the number of passes used.
	ArgonTime uint32

	// ArgonMemory is the amount of memory used in KiB.
	ArgonMemory uint32

	// ArgonThreads is the number of threads used.
	ArgonThreads uint8

	// ChunkSize is the length, in bytes, that the plaintext
	// will be splitted and encrypted with different nonces.
	ChunkSize int64
}

// NewParams creates an instance of Params struct with default configuration
func NewParams() *Params {
	params := new(Params)
	params.Check()
	return params
}

// Check checks if the Params fields are correctly filled. Correcting them
// when a field with the zero value is detected or returning an error
// if a field has an invalid value.
func (p *Params) Check() error {
	errInfoLevelString := "params: "

	if p.ArgonType == "" {
		p.ArgonType = ArgonType
	} else if p.ArgonType != ArgonType {
		return errors.New(errInfoLevelString + "invalid argon2 type")
	}

	if p.ArgonVersion == 0 {
		p.ArgonVersion = ArgonVersion
	} else if p.ArgonVersion != ArgonVersion {
		return errors.New(errInfoLevelString + "invalid argon2 version")
	}

	if p.SaltSize == 0 {
		p.SaltSize = SaltSize
	}
	if p.Salt != nil && len(p.Salt) != int(p.SaltSize) {
		return errors.New(errInfoLevelString + "salt is not the same size as salt size")
	}

	if p.ArgonTime == 0 {
		p.ArgonTime = ArgonTime
	}

	if p.ArgonMemory == 0 {
		p.ArgonMemory = ArgonMemory
	}

	if p.ArgonThreads == 0 {
		p.ArgonThreads = ArgonThreads
	}

	if p.ChunkSize == 0 {
		p.ChunkSize = ChunkSize
	} else if p.ChunkSize < 0 {
		return errors.New(errInfoLevelString + "chunk size too small")
	}

	return nil
}

// MarshalHeader returns a string header as a byte slice made from
// the Params fields. Returns an error if the Params used are not valid.
func (p *Params) MarshalHeader() ([]byte, error) {
	err := p.Check()
	if err != nil {
		return nil, err
	}

	salt := base64.RawStdEncoding.EncodeToString(p.Salt)
	s := fmt.Sprintf(
		"$%s$v=%d$t=%d,m=%d,p=%d$s=%s$b=%d\n",
		p.ArgonType,
		p.ArgonVersion,
		p.ArgonTime,
		p.ArgonMemory,
		p.ArgonThreads,
		salt,
		p.ChunkSize,
	)

	return []byte(s), nil
}

// ParseHeader parses the header of the given src stream.
// It create a new Params object and load its fields from the provided header.
func ParseHeader(src io.ReadSeeker) (*Params, error) {
	errInfoLevelString := "parsing header: "
	errParsing := errors.New(errInfoLevelString + "corrupted header")

	buff := bufio.NewReader(src)
	line, err := buff.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf(errInfoLevelString+"%w", err)
	}
	line = line[:len(line)-1]

	_, err = src.Seek(int64(len(line)+1), io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf(errInfoLevelString+"%w", err)
	}
	args := strings.Split(line, "$")
	if len(args) != 6 || args[0] != "" {
		fmt.Println("1")
		return nil, errParsing
	}

	var params Params
	params.ArgonType = args[1]

	values := strings.Split(args[2], "=")
	if len(values) != 2 || values[0] != "v" {
		fmt.Println("2")
		return nil, errParsing
	}
	u, err := strconv.ParseUint(values[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf(errInfoLevelString+"parsing argon2 version %w", err)
	}
	params.ArgonVersion = uint8(u)

	values = strings.Split(args[3], ",")
	if len(values) != 3 {
		fmt.Println("3")
		return nil, errParsing
	}

	subValues := strings.Split(values[0], "=")
	if len(subValues) != 2 || subValues[0] != "t" {
		fmt.Println("4")
		return nil, errParsing
	}
	u, err = strconv.ParseUint(subValues[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf(errInfoLevelString+"parsing argon2 time: %w", err)
	}
	params.ArgonTime = uint32(u)

	subValues = strings.Split(values[1], "=")
	if len(subValues) != 2 || subValues[0] != "m" {
		fmt.Println("5")
		return nil, errParsing
	}
	u, err = strconv.ParseUint(subValues[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf(errInfoLevelString+"parsing argon2 memory: %w", err)
	}
	params.ArgonMemory = uint32(u)

	subValues = strings.Split(values[2], "=")
	if len(subValues) != 2 || subValues[0] != "p" {
		fmt.Println("6")
		return nil, errParsing
	}
	u, err = strconv.ParseUint(subValues[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf(errInfoLevelString+"parsing argon2 threads: %w", err)
	}
	params.ArgonThreads = uint8(u)

	values = strings.Split(args[4], "=")
	if len(values) != 2 || values[0] != "s" {
		fmt.Println(values)
		fmt.Println("7")
		return nil, errParsing
	}
	params.Salt, err = base64.RawStdEncoding.DecodeString(values[1])
	if err != nil {
		return nil, fmt.Errorf(errInfoLevelString+"parsing salt: %w", err)
	}
	if len(params.Salt) > (1 << 8) {
		return nil, errors.New(errInfoLevelString + "parsing salt: salt too long")
	}
	params.SaltSize = uint8(len(params.Salt))

	values = strings.Split(args[5], "=")
	if len(values) != 2 || values[0] != "b" {
		fmt.Println("8")
		return nil, errParsing
	}
	i, err := strconv.ParseInt(values[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf(errInfoLevelString+"parsing chunk size: %w", err)
	}

	params.ChunkSize = int64(i)
	err = params.Check()
	if err != nil {
		return nil, fmt.Errorf(errInfoLevelString+"%w", err)
	}

	return &params, nil
}
