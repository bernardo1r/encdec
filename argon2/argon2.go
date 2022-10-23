package argon2

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	chacha "golang.org/x/crypto/chacha20poly1305"
)

const (
	ParamDelim   = " "
	HeaderPrefix = "argon2id"
)

const (
	SaltLen = 16

	ArgonTime = 3

	ArgonMemory = 1 << 22 //4 GiB

	ArgonThreads = 8
)

type ArgonKey struct {
	password []byte
	salt     []byte
	time     uint32
	memory   uint32
	threads  uint8
}

func NewArgonKey(password []byte) (*ArgonKey, error) {

	if len(password) == 0 {
		return nil, errors.New("password cannot have length 0")
	}

	salt := make([]byte, SaltLen)
	_, err := rand.Read(salt)
	//panic instead?
	if err != nil {
		return nil, err
	}

	argonKey := ArgonKey{
		salt:    salt,
		time:    ArgonTime,
		memory:  ArgonMemory,
		threads: ArgonThreads}

	argonKey.password = make([]byte, len(password))
	copy(argonKey.password, password)

	return &argonKey, nil
}

func (k *ArgonKey) setSalt(salt []byte) error {

	if len(salt) < 16 {
		return errors.New("salt length must be at least 16 bytes")
	}
	k.salt = make([]byte, len(salt))
	copy(k.salt, salt)

	return nil
}

func (k *ArgonKey) setParams(time uint32, memory uint32, threads uint8) error {

	if time == 0 {
		return errors.New("time parameter in argon2 key cannot be 0")
	}
	k.time = time

	if memory == 0 {
		return errors.New("memory parameter in argon2 key cannot be 0")
	}
	k.memory = memory

	if threads == 0 {
		return errors.New("number of threads parameter in argon2 key cannot be 0")
	}
	k.threads = threads

	return nil
}

func (k *ArgonKey) Key() []byte {
	return argon2.IDKey(k.password, k.salt, k.time, k.memory, k.threads, chacha.KeySize)
}

func (k *ArgonKey) Marshal() ([]byte, error) {

	var buf bytes.Buffer

	_, err := buf.WriteString("argon2id ")
	if err != nil {
		return nil, err
	}
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	_, err = encoder.Write(k.salt)
	if err != nil {
		return nil, err
	}
	err = encoder.Close()
	if err != nil {
		return nil, err
	}

	_, err = buf.WriteString(" " + strconv.FormatUint(uint64(k.time), 10) + " " +
		strconv.FormatUint(uint64(k.memory), 10) + " " +
		strconv.FormatUint(uint64(k.threads), 10))
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (k *ArgonKey) ParseHeader(header []byte) error {

	prefix, params, found := strings.Cut(string(header), ParamDelim)
	if len(prefix) == 0 || !found {
		return errors.New("could not find KDF used to generate key")
	}
	if prefix != HeaderPrefix {
		return fmt.Errorf("KDF %q not implemented", prefix)
	}

	args := strings.Split(params, ParamDelim)
	if len(args) != 4 {
		return errors.New("invalid number of argon2id parameters")
	}

	salt, err := base64.StdEncoding.DecodeString(string(args[0]))
	if err != nil {
		return fmt.Errorf("could not decode argon2 salt: %w", err)
	}

	time, err := strconv.ParseUint(string(args[1]), 10, 32)
	if err != nil {
		return fmt.Errorf("could not parse time parameter in argon2 key: %w", err)
	}
	memory, err := strconv.ParseUint(string(args[2]), 10, 32)
	if err != nil {
		return fmt.Errorf("could not parse memory parameter in argon2 key: %w", err)
	}
	threads, err := strconv.ParseUint(string(args[3]), 10, 8)
	if err != nil {
		return fmt.Errorf("could not parse number of threads parameter in argon2 key: %w", err)
	}

	err = k.setSalt(salt)
	if err != nil {
		return err
	}
	err = k.setParams(uint32(time), uint32(memory), uint8(threads))
	if err != nil {
		return err
	}

	return nil
}
