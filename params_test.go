package encdec

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"testing"

	"github.com/bernardo1r/encdec/internal/test/utils"
)

var paramsDefault = &Params{
	ArgonVersion: ArgonVersion,
	ArgonType: ArgonType,
	SaltSize: SaltSize,
	Salt: nil,
	ArgonTime: ArgonTime,
	ArgonMemory: ArgonMemory,
	ArgonThreads: ArgonThreads,
	ChunkSize: ChunkSize,
}

func compareParams(t *testing.T, expected *Params, actual *Params) bool {
	t.Helper()

	if expected.ArgonVersion != actual.ArgonVersion {
		t.Error("argon version: " + utils.SerrorDiff(expected.ArgonVersion, actual.ArgonVersion))
	}

	if expected.ArgonType != actual.ArgonType {
		t.Error("argon type: " + utils.SerrorDiff(expected.ArgonType, actual.ArgonType))
	}

	if expected.SaltSize != actual.SaltSize {
		t.Error("salt size: " + utils.SerrorDiff(expected.SaltSize, actual.SaltSize))
	}

	if !(expected.Salt == nil && actual.Salt == nil) && !bytes.Equal(expected.Salt, actual.Salt) {
		t.Error("salt: " + utils.SerrorDiff(expected.Salt, actual.Salt))
	}

	if expected.ArgonTime != actual.ArgonTime {
		t.Error("argon time: " + utils.SerrorDiff(expected.ArgonTime, actual.ArgonTime))
	}

	if expected.ArgonMemory != actual.ArgonMemory {
		t.Error("argon memory: " + utils.SerrorDiff(expected.ArgonMemory, actual.ArgonMemory))
	}

	if expected.ArgonThreads != actual.ArgonThreads {
		t.Error("argon threads: " + utils.SerrorDiff(expected.ArgonThreads, actual.ArgonThreads))
	}

	if expected.ChunkSize != actual.ChunkSize {
		t.Error("chunk size: " + utils.SerrorDiff(expected.ChunkSize, actual.ChunkSize))
	}

	return t.Failed()
}

func TestParamsCheck(t *testing.T) {
	t.Parallel()
	params := []struct {
		in *Params
		expected *Params
	}{
		{
			&Params{},
			paramsDefault,
		},
		{
			&Params{
				ArgonVersion: ArgonVersion,
			},
			paramsDefault,
		},
		{
			&Params{
				ArgonType: ArgonType,
			},
			paramsDefault,
		},
		{
			&Params{
				SaltSize: 12,
			},
			&Params{
				ArgonVersion: ArgonVersion,
				ArgonType: ArgonType,
				SaltSize: 12,
				Salt: nil,
				ArgonTime: ArgonTime,
				ArgonMemory: ArgonMemory,
				ArgonThreads: ArgonThreads,
				ChunkSize: ChunkSize,
			},
		},
		{
			&Params{
				Salt: []byte{0, 1, 2, 3, 4},
			},
			&Params{
				ArgonVersion: ArgonVersion,
				ArgonType: ArgonType,
				SaltSize: 5,
				Salt: []byte{0, 1, 2, 3, 4},
				ArgonTime: ArgonTime,
				ArgonMemory: ArgonMemory,
				ArgonThreads: ArgonThreads,
				ChunkSize: ChunkSize,
			},
		},
		{
			&Params{
				ArgonTime: 100,
			},
			&Params{
				ArgonVersion: ArgonVersion,
				ArgonType: ArgonType,
				SaltSize: SaltSize,
				Salt: nil,
				ArgonTime: 100,
				ArgonMemory: ArgonMemory,
				ArgonThreads: ArgonThreads,
				ChunkSize: ChunkSize,
			},
		},
		{
			&Params{
				ArgonMemory: 1,
			},
			&Params{
				ArgonVersion: ArgonVersion,
				ArgonType: ArgonType,
				SaltSize: SaltSize,
				Salt: nil,
				ArgonTime: ArgonTime,
				ArgonMemory: 1,
				ArgonThreads: ArgonThreads,
				ChunkSize: ChunkSize,
			},
		},
		{
			&Params{
				ArgonThreads: 200,
			},
			&Params{
				ArgonVersion: ArgonVersion,
				ArgonType: ArgonType,
				SaltSize: SaltSize,
				Salt: nil,
				ArgonTime: ArgonTime,
				ArgonMemory: ArgonMemory,
				ArgonThreads: 200,
				ChunkSize: ChunkSize,
			},
		},
		{
			&Params{
				ChunkSize: 1,
			},
			&Params{
				ArgonVersion: ArgonVersion,
				ArgonType: ArgonType,
				SaltSize: SaltSize,
				Salt: nil,
				ArgonTime: ArgonTime,
				ArgonMemory: ArgonMemory,
				ArgonThreads: ArgonThreads,
				ChunkSize: 1,
			},
		},
	}

	for idx, param := range params {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			p := *param.in
			paramCopy := &p
			
			err := paramCopy.Check()
			if err != nil {
				t.Fatalf("expected return: nil, got return: %v", err)
			}

			compareParams(t, param.expected, paramCopy)
		})
	}
}

func TestFailParamsCheck(t *testing.T) {
	t.Parallel()
	params := [] struct {
		in *Params
		err error
	}{
		{
			&Params{
				ArgonVersion: 10,
			},
			ErrArgonVersion,
		},
		{
			&Params{
				ArgonType: "argon2d",
			},
			ErrArgonType,
		},
		{
			&Params{
				Salt: make([]byte, (1 << 8) + 1),
			},
			ErrSalt,
		},
		{
			&Params{
				Salt: make([]byte, 99),
				SaltSize: 100,
			},
			ErrSaltSize,
		},
		{
			&Params{
				ChunkSize: -1,
			},
			ErrChunkSize,
		},
	}

	for idx, param := range params {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			t.Parallel()

			p := *param.in
			paramCopy := &p
			paramCopy.Salt = slices.Clone(param.in.Salt)

			err := paramCopy.Check()
			if err == nil {
				t.Errorf("expected return: <%v>, got return: nil", param.err)
				t.Errorf("before <%+v> ;; after <%v>", param, paramCopy)
				t.FailNow()
			}

			if !errors.Is(err, param.err) {
					t.Errorf("expected error not found: <%v>", param.err)
					t.Fatalf("got errors: <%v>", err)
				}
		})
	}
}

func TestParamsMarshalHeader(t *testing.T) {
	t.Parallel()
	salt := []byte{0, 1, 2, 3, 4}
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	customSalt := NewParams()
	customSalt.SaltSize = 0
	customSalt.Salt = salt

	params := [] struct {
		in *Params
		expected string
	}{
		{
			NewParams(),
			"$" + ArgonType +
			"$v=" + strconv.Itoa(int(ArgonVersion)) +
			"$t=" + strconv.Itoa(int(ArgonTime)) +
			",m=" + strconv.Itoa(int(ArgonMemory)) +
			",p=" + strconv.Itoa(int(ArgonThreads)) +
			"$s=" +
			"$b=" + strconv.Itoa(int(ChunkSize)) + "\n",
		},
		{
			customSalt,
			"$" + customSalt.ArgonType +
			"$v=" + strconv.Itoa(int(customSalt.ArgonVersion)) +
			"$t=" + strconv.Itoa(int(customSalt.ArgonTime)) +
			",m=" + strconv.Itoa(int(customSalt.ArgonMemory)) +
			",p=" + strconv.Itoa(int(customSalt.ArgonThreads)) +
			"$s=" + saltB64 +
			"$b=" + strconv.Itoa(int(customSalt.ChunkSize)) + "\n",
		},
	}

	for idx, param := range params {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			strBytes, err := param.in.MarshalHeader()
			if err != nil {
				t.Fatalf("expected return nil, got return: %v", err)
			}

			str := string(strBytes)
			if str != param.expected {
				t.Fatal(utils.SerrorDiff(param.expected, str))
			}
		})
	}
}

func TestParseHeader(t *testing.T) {
	t.Parallel()
	salt := []byte{0, 1, 2, 3, 4}
	param := NewParams()
	param.SaltSize = uint8(len(salt))
	param.Salt = salt

	params := []struct {
		in string
		expected *Params
		errors []error
	}{
		// Correct
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			nil,
		},

		// Parse only
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$s=AAECAwQ$b=65536",
			param,
			[]error{ErrParsing},
		},
		{
			"argon2id$v=19$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2idv=19$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=4s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$s=AAECAwQb=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$=19$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v19$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$19$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1m=2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,=2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,m2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,2097152,p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,m=2097152p=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,=4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,4$s=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$=AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$sAAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$AAECAwQ$b=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$s=AAECAwQ$=65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$s=AAECAwQ$b65536\n",
			param,
			[]error{ErrParsing},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$s=AAECAwQ$65536\n",
			param,
			[]error{ErrParsing},
		},

		// Argon type
		{
			"$argon2i$v=19$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrArgonType},
		},
		{
			"$$v=19$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrArgonType},
		},

		// Argon version
		{
			"$argon2id$v=1$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrArgonVersion},
		},
		{
			"$argon2id$v=$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonVersion},
		},
		{
			"$argon2id$v=0$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrArgonVersion},
		},
		{
			"$argon2id$v=300$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonVersion},
		},
		{
			"$argon2id$v=-1$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonVersion},
		},
		{
			"$argon2id$v=a$t=1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonVersion},
		},

		// Argon time
		{
			"$argon2id$v=19$t=,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonTime},
		},
		{
			"$argon2id$v=19$t=0,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrArgonTime},
		},
		{
			"$argon2id$v=19$t=" + strconv.Itoa(1 << 32) + ",m=2097152,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonTime},
		},
		{
			"$argon2id$v=19$t=-1,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonTime},
		},
		{
			"$argon2id$v=19$t=a,m=2097152,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonTime},
		},

		// Argon memory
		{
			"$argon2id$v=19$t=1,m=,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonMemory},
		},
		{
			"$argon2id$v=19$t=1,m=0,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrArgonMemory},
		},
		{
			"$argon2id$v=19$t=1,m=" + strconv.Itoa(1 << 32) + ",p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonMemory},
		},
		{
			"$argon2id$v=19$t=1,m=-1,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonMemory},
		},
		{
			"$argon2id$v=19$t=1,m=a,p=4$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonMemory},
		},

		// Argon threads
		{
			"$argon2id$v=19$t=1,m=2097152,p=$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonThreads},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=0$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrArgonThreads},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=300$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonThreads},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=-1$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonThreads},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=a$s=AAECAwQ$b=65536\n",
			nil,
			[]error{ErrParsing, ErrArgonThreads},
		},

		// Salt
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$s=$b=65536\n",
			nil,
			[]error{ErrSalt},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$s=" +
			"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE" +
			"$b=65536\n",
			nil,
			[]error{ErrSalt},
		},

		// Chunk size
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$s=AAECAwQ$b=\n",
			nil,
			[]error{ErrParsing, ErrChunkSize},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$s=AAECAwQ$b=0\n",
			nil,
			[]error{ErrChunkSize},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$s=AAECAwQ$b=" +
			"9223372036854775808" +
			"\n",
			nil,
			[]error{ErrParsing, ErrChunkSize},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$s=AAECAwQ$b=-1\n",
			nil,
			[]error{ErrChunkSize},
		},
		{
			"$argon2id$v=19$t=1,m=2097152,p=4$s=AAECAwQ$b=a\n",
			nil,
			[]error{ErrParsing, ErrChunkSize},
		},

	}

	for idx, param := range params {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			t.Parallel()
			buffer := bufio.NewReader(bytes.NewBuffer([]byte(param.in)))
			p, err := ParseHeader(buffer)
			if param.errors == nil {
				if err != nil {
					t.Fatalf("expected return nil, got return: %v", err)
				}

				if compareParams(t, param.expected, p) {
					t.FailNow()
				}
				return
			}

			if err == nil {
				t.Fatalf("expected return: <%v>, got return: nil", param.errors)
			}

			for _, expectedErr := range param.errors {
				if !errors.Is(err, expectedErr) {
					t.Errorf("expected error not found: <%v>", expectedErr)
					t.Fatalf("got errors: <%v>", err)
				}
			}
		})
	}
}
