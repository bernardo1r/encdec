package encdec

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Default values of params field.
const (
	ArgonVersion = 19
	ArgonType    = "argon2id"
	SaltSize     = 16 // 16 Bytes
	ArgonTime    = 1
	ArgonMemory  = 1 << 21 // 2 MiB * KiB = 2 GiB
	ArgonThreads = 4
	ChunkSize    = 64 * (1 << 10) // 64 KiB
)

// Params represents the parameters used to generate a symmetric key using
// Argon2 and the chunk size in bytes for splitting the payload before
// encrypting they with unique nonces.
//
// The zero value is ready to use.
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
	if p.ArgonType == "" {
		p.ArgonType = ArgonType
	} else if p.ArgonType != ArgonType {
		return ErrArgonType
	}

	if p.ArgonVersion == 0 {
		p.ArgonVersion = ArgonVersion
	} else if p.ArgonVersion != ArgonVersion {
		return ErrArgonVersion
	}

	if p.Salt != nil {
		if len(p.Salt) > (1 << 8) {
			return ErrSalt
		}

		if p.SaltSize != 0 && int(p.SaltSize) != len(p.Salt) {
			return ErrSaltSize
		}

		p.SaltSize = uint8(len(p.Salt))
	} else {
		if p.SaltSize == 0 {
			p.SaltSize = SaltSize
		}
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
		return ErrChunkSize
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

func parseArgonParams(params *Params, value string) error {
	values := strings.Split(value, ",")
	if len(values) != 3 {
		return ErrParsing
	}

	// Argon time
	subValues := strings.Split(values[0], "=")
	if len(subValues) != 2 || subValues[0] != "t" {
		return ErrParsing
	}
	u, err := strconv.ParseUint(subValues[1], 10, 32)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrParsing, ErrArgonTime)
	}
	if u == 0 {
		return ErrArgonTime
	}
	params.ArgonTime = uint32(u)

	// Argon memory
	subValues = strings.Split(values[1], "=")
	if len(subValues) != 2 || subValues[0] != "m" {
		return ErrParsing
	}
	u, err = strconv.ParseUint(subValues[1], 10, 32)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrParsing, ErrArgonMemory)
	}
	if u == 0 {
		return ErrArgonMemory
	}
	params.ArgonMemory = uint32(u)

	// Argon threads
	subValues = strings.Split(values[2], "=")
	if len(subValues) != 2 || subValues[0] != "p" {
		return ErrParsing
	}
	u, err = strconv.ParseUint(subValues[1], 10, 8)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrParsing, ErrArgonThreads)
	}
	if u == 0 {
		return ErrArgonThreads
	}
	params.ArgonThreads = uint8(u)

	return nil
}

// ParseHeader parses the header of the given src stream.
// It create a new Params object and load its fields from the provided header.
func ParseHeader(src *bufio.Reader) (*Params, error) {

	line, err := src.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParsing, err)
	}
	line = line[:len(line)-1]

	args := strings.Split(line, "$")
	if len(args) != 6 || args[0] != "" {
		return nil, ErrParsing
	}

	var params Params
	params.ArgonType = args[1]
	if len(params.ArgonType) == 0 {
		return nil, ErrArgonType
	}

	// Argon version
	values := strings.Split(args[2], "=")
	if len(values) != 2 || values[0] != "v" {
		return nil, ErrParsing
	}
	u, err := strconv.ParseUint(values[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParsing, ErrArgonVersion)
	}
	if u == 0 {
		return nil, ErrArgonVersion
	}
	params.ArgonVersion = uint8(u)

	// Argon params
	err = parseArgonParams(&params, args[3])
	if err != nil {
		return nil, err
	}

	// Salt
	values = strings.Split(args[4], "=")
	if len(values) != 2 || values[0] != "s" {
		return nil, ErrParsing
	}
	params.Salt, err = base64.RawStdEncoding.DecodeString(values[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParsing, ErrSalt)
	}
	if len(params.Salt) == 0 {
		return nil, ErrSalt
	}

	// Chunk size
	values = strings.Split(args[5], "=")
	if len(values) != 2 || values[0] != "b" {
		return nil, ErrParsing
	}
	i, err := strconv.ParseInt(values[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParsing, ErrChunkSize)
	}
	if i <= 0 {
		return nil, ErrChunkSize
	}
	params.ChunkSize = i

	return &params, params.Check()
}
