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

const (
	ArgonType    = "argon2id"
	ArgonVersion = 19
	SaltSize     = 16
	ArgonTime    = 10
	ArgonMemory  = 1 << 22
	ArgonThreads = 8
	ChunkSize    = 64 * (1 << 10) //64 KiB
)

type Params struct {
	ArgonType    string
	ArgonVersion uint8
	SaltSize     uint8
	Salt         []byte
	ArgonTime    uint32
	ArgonMemory  uint32
	ArgonThreads uint8
	ChunkSize    int64
}

func (p *Params) Check() error {
	errLevelInfoString := "params: "

	if p.ArgonType == "" {
		p.ArgonType = ArgonType
	} else if p.ArgonType != ArgonType {
		return errors.New(errLevelInfoString + "invalid argon2 type")
	}

	if p.ArgonVersion == 0 {
		p.ArgonVersion = ArgonVersion
	} else if p.ArgonVersion != ArgonVersion {
		return errors.New(errLevelInfoString + "invalid argon2 version")
	}

	if p.SaltSize == 0 {
		p.SaltSize = SaltSize
	}
	if p.Salt != nil && len(p.Salt) != int(p.SaltSize) {
		return errors.New(errLevelInfoString + "salt is not the same size as salt size")
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
		return errors.New(errLevelInfoString + "chunk size too small")
	}

	return nil
}

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

func ParseHeader(src io.ReadSeeker) (*Params, error) {
	errLevelInfoString := "parsing header: "
	errParsing := errors.New(errLevelInfoString + "corrupted header")

	buff := bufio.NewReader(src)
	line, err := buff.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf(errLevelInfoString+"%w", err)
	}
	line = line[:len(line)-1]

	_, err = src.Seek(int64(len(line)+1), io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf(errLevelInfoString+"%w", err)
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
		return nil, fmt.Errorf(errLevelInfoString+"parsing argon2 version %w", err)
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
		return nil, fmt.Errorf(errLevelInfoString+"parsing argon2 time: %w", err)
	}
	params.ArgonTime = uint32(u)

	subValues = strings.Split(values[1], "=")
	if len(subValues) != 2 || subValues[0] != "m" {
		fmt.Println("5")
		return nil, errParsing
	}
	u, err = strconv.ParseUint(subValues[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf(errLevelInfoString+"parsing argon2 memory: %w", err)
	}
	params.ArgonMemory = uint32(u)

	subValues = strings.Split(values[2], "=")
	if len(subValues) != 2 || subValues[0] != "p" {
		fmt.Println("6")
		return nil, errParsing
	}
	u, err = strconv.ParseUint(subValues[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf(errLevelInfoString+"parsing argon2 threads: %w", err)
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
		return nil, fmt.Errorf(errLevelInfoString+"parsing salt: %w", err)
	}
	if len(params.Salt) > (1 << 8) {
		return nil, errors.New(errLevelInfoString + "parsing salt: salt too long")
	}
	params.SaltSize = uint8(len(params.Salt))

	values = strings.Split(args[5], "=")
	if len(values) != 2 || values[0] != "b" {
		fmt.Println("8")
		return nil, errParsing
	}
	i, err := strconv.ParseInt(values[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf(errLevelInfoString+"parsing chunk size: %w", err)
	}

	params.ChunkSize = int64(i)
	err = params.Check()
	if err != nil {
		return nil, fmt.Errorf(errLevelInfoString+"%w", err)
	}

	return &params, nil
}
