package main_test

import (
	"errors"
	"flag"
	"log"
	"os"
	"os/exec"
	"testing"

	"github.com/bernardo1r/encdec/internal/test/utils"
)

const MainPath = "encdec.go"

var dirs *utils.Dirs

type commandHelper struct {
	ExecName         string
	ExecArgs         []string
	CmdOptions       []utils.CmdOptions
	ExitCodeExpected int
}

func ignoreExitError(err error) error {
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return nil
	}
	if err != nil {
		return err
	}
	return nil
}

func execCommand(t *testing.T, helper *commandHelper) {
	t.Helper()
	cmd, err := utils.NewCmd(
		exec.Command(helper.ExecName, helper.ExecArgs...),
		helper.CmdOptions...,
	)
	if err != nil {
		t.Fatal(err)
	}

	err = cmd.Run()
	err = ignoreExitError(err)
	if err != nil {
		t.Fatal(err)
	}

	exitCode := cmd.ProcessState.ExitCode()
	if exitCode != helper.ExitCodeExpected {
		t.Fatalf("expected: exit code %v, got: exit code %v\n", helper.ExitCodeExpected, exitCode)
	}
}

func TestFailNoStdinNoStdout(t *testing.T) {
	t.Parallel()
	helper := commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-e", "-p", "hello"},
		CmdOptions: []utils.CmdOptions{
			utils.WithStdin(),
			utils.WithStdout(),
		},
		ExitCodeExpected: 1,
	}
	execCommand(t, &helper)
}

func TestFailNoStdin(t *testing.T) {
	t.Parallel()
	session := dirs.Session()
	t.Cleanup(session.Close)

	outputfilepath, err := session.RandomFilename()
	if err != nil {
		t.Fatal(err)
	}

	helper := commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-e", "-p", "hello"},
		CmdOptions: []utils.CmdOptions{
			utils.WithStdin(),
			utils.WithOutputFile(outputfilepath),
		},
		ExitCodeExpected: 1,
	}
	execCommand(t, &helper)
}

func TestFailNoStdout(t *testing.T) {
	t.Parallel()
	helper := commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-e", "-p", "hello", dirs.CommandPath()},
		CmdOptions: []utils.CmdOptions{
			utils.WithInputFile(dirs.CommandPath()),
			utils.WithStdout(),
		},
		ExitCodeExpected: 1,
	}
	execCommand(t, &helper)
}

func TestFailStdinAndFilename(t *testing.T) {
	t.Parallel()
	session := dirs.Session()
	t.Cleanup(session.Close)

	outputfilepath, err := session.RandomFilename()
	if err != nil {
		t.Fatal(err)
	}

	helper := commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-e", "-p", "hello", dirs.CommandPath()},
		CmdOptions: []utils.CmdOptions{
			utils.WithInputFile(dirs.CommandPath()),
			utils.WithOutputFile(outputfilepath),
		},
		ExitCodeExpected: 1,
	}
	execCommand(t, &helper)
}

func TestStdin(t *testing.T) {
	t.Parallel()
	session := dirs.Session()
	t.Cleanup(session.Close)

	password := "hello"
	filepath1, err := session.RandomFilename()
	if err != nil {
		t.Fatal(err)
	}
	helper := commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-e", "-p", password},
		CmdOptions: []utils.CmdOptions{
			utils.WithInputFile(dirs.CommandPath()),
			utils.WithOutputFile(filepath1),
		},
		ExitCodeExpected: 0,
	}
	execCommand(t, &helper)

	filepath2, err := session.RandomFilename()
	if err != nil {
		t.Fatal(err)
	}
	helper = commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-p", password},
		CmdOptions: []utils.CmdOptions{
			utils.WithInputFile(filepath1),
			utils.WithOutputFile(filepath2),
		},
		ExitCodeExpected: 0,
	}
	execCommand(t, &helper)

	ok, err := utils.Diff(dirs.CommandPath(), filepath2)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("files are not equal")
	}
}

func TestInputFile(t *testing.T) {
	t.Parallel()
	session := dirs.Session()
	t.Cleanup(session.Close)

	password := "hello"
	filepath1, err := session.RandomFilename()
	if err != nil {
		t.Fatal(err)
	}

	helper := commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-e", "-p", password},
		CmdOptions: []utils.CmdOptions{
			utils.WithInputFile(dirs.CommandPath()),
			utils.WithOutputFile(filepath1),
		},
		ExitCodeExpected: 0,
	}
	execCommand(t, &helper)

	filepath2, err := session.RandomFilename()
	if err != nil {
		t.Fatal(err)
	}
	helper = commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-p", password},
		CmdOptions: []utils.CmdOptions{
			utils.WithInputFile(filepath1),
			utils.WithOutputFile(filepath2),
		},
		ExitCodeExpected: 0,
	}
	execCommand(t, &helper)

	ok, err := utils.Diff(dirs.CommandPath(), filepath2)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("files are not equal")
	}
}

func TestArgumentFile(t *testing.T) {
	t.Parallel()
	session := dirs.Session()
	t.Cleanup(session.Close)

	password := "hello"
	filepath1, err := session.RandomFilename()
	if err != nil {
		t.Fatal(err)
	}

	helper := commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-e", "-p", password, dirs.CommandPath()},
		CmdOptions: []utils.CmdOptions{
			utils.WithStdin(),
			utils.WithOutputFile(filepath1),
		},
		ExitCodeExpected: 0,
	}
	execCommand(t, &helper)

	filepath2, err := session.RandomFilename()
	if err != nil {
		t.Fatal(err)
		t.FailNow()
	}
	helper = commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-p", password, filepath1},
		CmdOptions: []utils.CmdOptions{
			utils.WithStdin(),
			utils.WithOutputFile(filepath2),
		},
		ExitCodeExpected: 0,
	}
	execCommand(t, &helper)

	ok, err := utils.Diff(dirs.CommandPath(), filepath2)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("files are not equal")
	}
}

func TestInputAndArgumentFile(t *testing.T) {
	t.Parallel()
	session := dirs.Session()
	t.Cleanup(session.Close)

	password := "hello"
	filepath1, err := session.RandomFilename()
	if err != nil {
		t.Fatal(err)
	}

	helper := commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-e", "-p", password},
		CmdOptions: []utils.CmdOptions{
			utils.WithInputFile(dirs.CommandPath()),
			utils.WithOutputFile(filepath1),
		},
		ExitCodeExpected: 0,
	}
	execCommand(t, &helper)

	filepath2, err := session.RandomFilename()
	if err != nil {
		t.Fatal(err)
	}
	helper = commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-p", password, filepath1},
		CmdOptions: []utils.CmdOptions{
			utils.WithStdin(),
			utils.WithOutputFile(filepath2),
		},
		ExitCodeExpected: 0,
	}
	execCommand(t, &helper)

	ok, err := utils.Diff(dirs.CommandPath(), filepath2)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("files are not equal")
		t.FailNow()
	}
}

func TestArgumentAndInputFile(t *testing.T) {
	t.Parallel()
	session := dirs.Session()
	t.Cleanup(session.Close)

	password := "hello"
	filepath1, err := session.RandomFilename()
	if err != nil {
		t.Fatal(err)
	}

	helper := commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-e", "-p", password, dirs.CommandPath()},
		CmdOptions: []utils.CmdOptions{
			utils.WithStdin(),
			utils.WithOutputFile(filepath1),
		},
		ExitCodeExpected: 0,
	}
	execCommand(t, &helper)

	filepath2, err := session.RandomFilename()
	if err != nil {
		t.Fatal(err)
	}
	helper = commandHelper{
		ExecName: dirs.CommandPath(),
		ExecArgs: []string{"-p", password},
		CmdOptions: []utils.CmdOptions{
			utils.WithInputFile(filepath1),
			utils.WithOutputFile(filepath2),
		},
		ExitCodeExpected: 0,
	}
	execCommand(t, &helper)

	ok, err := utils.Diff(dirs.CommandPath(), filepath2)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("files are not equal")
	}
}

func TestMain(m *testing.M) {
	var (
		binaryPath string
		mainPath   string
	)
	flag.StringVar(&binaryPath, "b", "", "path to encdec binary file to be tested "+
		"(with compiled test this flag or 'src' flag must be provided)",
	)
	flag.StringVar(&mainPath, "src", "", "path to encdec main source file to be tested "+
		"(with compiled test this flag or 'b' flag must be provided)",
	)
	flag.Parse()

	if len(binaryPath) != 0 && len(mainPath) != 0 {
		log.Println("Both 'src' and 'b' flag provided")
		flag.Usage()
		os.Exit(1)
	}

	log.SetFlags(log.Llongfile)

	var (
		programPath string
		compile     bool
	)
	switch {
	case len(binaryPath) > 0:
		programPath = binaryPath
	case len(mainPath) > 0:
		programPath = mainPath
		compile = true
	default:
		programPath = MainPath
		compile = true
	}
	var err error
	dirs, err = utils.NewDirs("tests", programPath, compile)
	if err != nil {
		log.Fatalln(err)
	}

	code := m.Run()

	err = dirs.TearDown()
	if err != nil {
		log.Fatalln(err)
	}

	os.Exit(code)
}
