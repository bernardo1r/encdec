package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bernardo1r/encdec/internal/tui"
	"golang.org/x/sync/errgroup"
)

func Diff(filepath1 string, filepath2 string) (ok bool, err error) {
	hasher1 := sha256.New()
	hasher2 := sha256.New()

	file1, err := os.Open(filepath1)
	if err != nil {
		return false, err
	}
	defer func() {
		err2 := file1.Close()
		if err2 != nil && err == nil {
			err = err2
		}
	}()

	file2, err := os.Open(filepath2)
	if err != nil {
		return false, err
	}
	defer func() {
		err2 := file2.Close()
		if err2 != nil && err == nil {
			err = err2
		}
	}()

	var g errgroup.Group
	g.Go(func() error {
		_, err := io.Copy(hasher1, file1)
		return err
	})
	g.Go(func() error {
		_, err := io.Copy(hasher2, file2)
		return err
	})

	err = g.Wait()
	if err != nil {
		return false, err
	}

	ok = bytes.Equal(hasher1.Sum(nil), hasher2.Sum(nil))
	return ok, nil
}

func FileSize(filepath string) (int64, error) {
	finfo, err := os.Stat(filepath)
	if err != nil {
		return 0, nil
	}

	return finfo.Size(), nil
}

type Dirs struct {
	// Path where test artifacts are going to be created
	testObjectsDir        string
	testObjectsDirCreated bool
	// Main program path to be tested
	commandPath string
}

func trimExt(filename string) string {
	ext := filepath.Ext(filename)
	return strings.TrimSuffix(filename, ext)
}

func addExecutableExt(filename string) string {
	if runtime.GOOS == "windows" {
		filename = filename + ".exe"
	}
	return filename
}

func (dirs *Dirs) compile() error {
	binaryPath := trimExt(filepath.Base(dirs.commandPath)) + "_test"
	binaryPath = addExecutableExt(binaryPath)
	binaryPath = filepath.Join(dirs.testObjectsDir, binaryPath)

	oldDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting current dir: %w", err)
	}
	binaryAbsPath := filepath.Join(oldDir, binaryPath)

	err = os.Chdir(filepath.Dir(dirs.commandPath))
	if err != nil {
		return fmt.Errorf("changing dir to the provided encdec source file: %w", err)
	}

	cmd := exec.Command("go", "build", "-o", binaryAbsPath, filepath.Base(dirs.commandPath))
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("compiling go program: %w", err)
	}

	err = os.Chdir(oldDir)
	if err != nil {
		return fmt.Errorf("changing dir back to old dir: %w", err)
	}

	size, err := FileSize(binaryPath)
	if err != nil {
		return fmt.Errorf("could not get file size of the go compiled program: %w", err)
	}
	if size == 0 {
		return errors.New("empty compiled go program")
	}

	dirs.commandPath = binaryPath
	return nil
}

func (dirs *Dirs) setup(compile bool) error {
	err := os.Mkdir(dirs.testObjectsDir, 0777)
	if err != nil {
		err = os.RemoveAll(dirs.testObjectsDir)
		if err != nil {
			return fmt.Errorf("cleaning/deleting test objects dir: %w", err)
		}
		err := os.Mkdir(dirs.testObjectsDir, 0777)
		if err != nil {
			return fmt.Errorf("creating test objects dir: %w", err)
		}
	}
	dirs.testObjectsDirCreated = true

	if compile {
		err = dirs.compile()
	}
	return err
}

func NewDirs(testObjectsDir string, programPath string, compile bool) (*Dirs, error) {
	dirs := &Dirs{
		testObjectsDir: testObjectsDir,
		commandPath:    programPath,
	}

	err := dirs.setup(compile)
	if err != nil {
		var err2 error
		if dirs.testObjectsDirCreated {
			err2 = os.RemoveAll(dirs.testObjectsDir)
			if err2 != nil {
				err2 = fmt.Errorf("could not delete test objects dir: %w", err2)
			}
		}
		return nil, errors.Join(err, err2)
	}
	dirs.commandPath = "./" + dirs.commandPath

	return dirs, nil
}

func (dirs *Dirs) TearDown() error {
	err := os.RemoveAll(dirs.testObjectsDir)
	dirs.testObjectsDir = ""
	dirs.commandPath = ""
	if err != nil {
		return fmt.Errorf("could not delete test objects dir: %w", err)
	}
	return nil
}

func (dirs *Dirs) ObjectsDir() string {
	return dirs.testObjectsDir
}

func (dirs *Dirs) CommandPath() string {
	return dirs.commandPath
}

type Session struct {
	filepaths []string
	*Dirs
}

func (dirs *Dirs) Session() *Session {
	return &Session{
		Dirs:      dirs,
		filepaths: make([]string, 0),
	}
}

func (session *Session) Close() {
	for _, filepath := range session.filepaths {
		os.Remove(filepath)
	}
}

func (session *Session) RandomFilename() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	name := base64.RawURLEncoding.EncodeToString(b)
	filename := filepath.Join(session.testObjectsDir, name)
	session.filepaths = append(session.filepaths, filename)

	return filename, nil
}

type Cmd struct {
	closers map[string]io.Closer
	*exec.Cmd
}

type cmdConfig struct {
	inputfile       string
	createInputfile bool
	stdin           bool
	outputfile      string
	stdout          bool
}

type CmdOptions func(*cmdConfig) error

func WithStdin() CmdOptions {
	return func(config *cmdConfig) error {
		if config.inputfile != "" {
			return errors.New("input file already configured")
		}
		config.stdin = true
		return nil
	}
}

func WithStdout() CmdOptions {
	return func(config *cmdConfig) error {
		if config.outputfile != "" {
			return errors.New("output file already configured")
		}
		config.stdout = true
		return nil
	}
}

func WithInputFile(filepath string) CmdOptions {
	return func(config *cmdConfig) error {
		switch {
		case config.stdin:
			return errors.New("stdin already configured")
		case config.inputfile != "":
			return errors.New("intput file already configured")
		default:
			config.inputfile = filepath
		}
		return nil
	}
}

func WithOutputFile(filepath string) CmdOptions {
	return func(config *cmdConfig) error {
		switch {
		case config.stdout:
			return errors.New("stdout already configured")
		case config.outputfile != "":
			return errors.New("output file already configured")
		default:
			config.outputfile = filepath
		}
		return nil
	}
}

func (cmd *Cmd) closeAll() error {
	var err error
	for key, closer := range cmd.closers {
		err2 := closer.Close()
		if err2 != nil {
			err2 = fmt.Errorf("closing %s: %w", key, err2)
			err = errors.Join(err, err2)
		}
	}

	return err
}

func NewCmd(cmd *exec.Cmd, options ...CmdOptions) (c *Cmd, err error) {
	config := cmdConfig{}
	for _, opt := range options {
		err := opt(&config)
		if err != nil {
			return nil, err
		}
	}

	c = &Cmd{
		closers: make(map[string]io.Closer),
		Cmd:     cmd,
	}

	defer func(c *Cmd) {
		if err != nil {
			err2 := c.closeAll()
			err = errors.Join(err, err2)
		}
	}(c)

	if config.inputfile != "" {
		var file *os.File
		file, err = os.Open(config.inputfile)
		if err != nil {
			return nil, fmt.Errorf("could not open input file %s: %w", config.inputfile, err)
		}
		c.closers["input file"] = file
		c.Stdin = file
	}

	if config.outputfile != "" {
		file, err := os.Create(config.outputfile)
		if err != nil {
			return nil, fmt.Errorf("could not create output file %s: %w", config.outputfile, err)
		}
		c.closers["output file"] = file
		c.Stdout = file
	}

	var tty *tui.TTY
	if config.stdin {
		tty, err = tui.NewTTY()
		if err != nil {
			return nil, err
		}
		c.closers["terminal"] = tty
		c.Stdin = tty.In()
	}

	if config.stdout {
		if !config.stdin {
			tty, err = tui.NewTTY()
			if err != nil {
				return nil, err
			}
			c.closers["terminal"] = tty
		}
		c.Stdout = tty.Out()
	}

	return c, nil
}

func (cmd *Cmd) Run() error {
	err := cmd.Cmd.Run()
	return errors.Join(err, cmd.closeAll())
}
