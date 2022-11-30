package builder

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/alexflint/go-filemutex"
	"github.com/otiai10/copy"
	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/fileutil"
)

type CIFuzzBuilder struct {
	Options

	projectDir string
	mutex      *filemutex.FileMutex
	isLocked   bool
}

type Options struct {
	Version   string
	TargetDir string
	GOOS      string
	GOARCH    string
}

func NewCIFuzzBuilder(opts Options) (*CIFuzzBuilder, error) {
	var err error

	// Validate options
	if opts.Version == "" {
		return nil, err
	}
	opts.TargetDir, err = validateTargetDir(opts.TargetDir)
	if err != nil {
		return nil, err
	}

	opts.TargetDir, err = filepath.Abs(opts.TargetDir)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	projectDir, err := FindProjectDir()
	if err != nil {
		return nil, err
	}

	i := &CIFuzzBuilder{
		Options:    opts,
		projectDir: projectDir,
	}

	i.mutex, err = filemutex.New(i.lockFile())
	if err != nil {
		// filemutex.New returns errors from syscall.Open without the
		// path, so we wrap it in the os.PathError same as os.Open does.
		return nil, errors.WithStack(&os.PathError{Op: "open", Path: i.lockFile(), Err: err})
	}

	err = i.createDirectoryLayout()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	log.Printf("Building cifuzz in %v", opts.TargetDir)

	return i, nil
}

func (i *CIFuzzBuilder) createDirectoryLayout() error {
	err := os.MkdirAll(i.binDir(), 0755)
	if err != nil {
		i.Cleanup()
		return errors.WithStack(err)
	}
	err = os.MkdirAll(i.libDir(), 0755)
	if err != nil {
		i.Cleanup()
		return errors.WithStack(err)
	}
	err = os.MkdirAll(i.shareDir(), 0755)
	if err != nil {
		i.Cleanup()
		return errors.WithStack(err)
	}

	return nil
}

func (i *CIFuzzBuilder) binDir() string {
	return filepath.Join(i.TargetDir, "bin")
}

func (i *CIFuzzBuilder) libDir() string {
	return filepath.Join(i.TargetDir, "lib")
}

func (i *CIFuzzBuilder) shareDir() string {
	return filepath.Join(i.TargetDir, "share", "cifuzz")
}

func (i *CIFuzzBuilder) lockFile() string {
	return filepath.Join(i.projectDir, ".installer-lock")
}

func (i *CIFuzzBuilder) Cleanup() {
	fileutil.Cleanup(i.TargetDir)
	// Always remove the lock file, even if SKIP_CLEANUP is set, because
	// keeping it around is not useful for debugging purposes.
	_ = os.Remove(i.lockFile())
}

// Lock acquires a file lock to make sure that only one instance of the
// installer is executed at the same time. Note that this function does
// not provide thread-safety for using the same installer instance
// multiple times.
func (i *CIFuzzBuilder) Lock() error {
	if i.isLocked {
		return nil
	}
	err := i.mutex.Lock()
	if err != nil {
		return errors.WithStack(err)
	}
	i.isLocked = true
	return nil

}

// Unlock releases the file lock to allow other installer instances to
// run.
func (i *CIFuzzBuilder) Unlock() error {
	if !i.isLocked {
		return nil
	}
	err := i.mutex.Unlock()
	if err != nil {
		return errors.WithStack(err)
	}
	i.isLocked = false
	return nil
}

func (i *CIFuzzBuilder) BuildCIFuzzAndDeps() error {
	var err error

	err = i.Lock()
	if err != nil {
		return err
	}
	defer func() {
		err = i.Unlock()
		if err != nil {
			log.Printf("error: %v", err)
		}
	}()

	if runtime.GOOS == "linux" {
		err = i.BuildMinijail()
		if err != nil {
			return err
		}

		err = i.BuildProcessWrapper()
		if err != nil {
			return err
		}
	}

	err = i.BuildCIFuzz()
	if err != nil {
		return err
	}

	err = i.CopyCMakeIntegration()
	if err != nil {
		return err
	}

	err = i.CopySharedFolder()
	if err != nil {
		return err
	}

	return nil
}

func (i *CIFuzzBuilder) BuildMinijail() error {
	var err error

	err = i.Lock()
	if err != nil {
		return err
	}
	defer func() {
		err = i.Unlock()
		if err != nil {
			log.Printf("error: %v", err)
		}
	}()

	minijailDir := filepath.Join(i.projectDir, "third-party", "minijail")

	// Build minijail
	cmd := exec.Command("make", "CC_BINARY(minijail0)")
	cmd.Dir = minijailDir
	// The minijail Makefile changes the directory to $PWD, so we have
	// to set that.
	cmd.Env, err = envutil.Setenv(os.Environ(), "PWD", filepath.Join(i.projectDir, "third-party", "minijail"))
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	log.Printf("Command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		return errors.WithStack(err)
	}

	// Copy minijail binary
	src := filepath.Join(i.projectDir, "third-party", "minijail", "minijail0")
	dest := filepath.Join(i.binDir(), "minijail0")
	err = copy.Copy(src, dest)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (i *CIFuzzBuilder) BuildProcessWrapper() error {
	var err error
	err = i.Lock()
	if err != nil {
		return err
	}
	defer func() {
		err = i.Unlock()
		if err != nil {
			log.Printf("error: %v", err)
		}
	}()

	// Build process wrapper
	compiler := os.Getenv("CC")
	if compiler == "" {
		compiler = "clang"
	}
	dest := filepath.Join(i.libDir(), "process_wrapper")
	cmd := exec.Command(compiler, "-o", dest, "process_wrapper.c")
	cmd.Dir = filepath.Join(i.projectDir, "pkg", "minijail", "process_wrapper", "src")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	log.Printf("Command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (i *CIFuzzBuilder) BuildCIFuzz() error {
	var err error
	err = i.Lock()
	if err != nil {
		return err
	}
	defer func() {
		err = i.Unlock()
		if err != nil {
			log.Printf("error: %v", err)
		}
	}()

	// Add GOOS and GOARCH envs to support cross compilation
	buildEnv := os.Environ()
	buildEnv = append(buildEnv, []string{"GOOS=" + i.GOOS, "GOARCH=" + i.GOARCH}...)

	// Build cifuzz
	ldFlags := fmt.Sprintf("-ldflags=-X code-intelligence.com/cifuzz/internal/cmd/root.version=%s", i.Version)
	cifuzz := filepath.Join(i.projectDir, "cmd", "cifuzz", "main.go")
	cmd := exec.Command("go", "build", "-o", CIFuzzExecutablePath(i.binDir()), ldFlags, cifuzz)
	cmd.Dir = i.projectDir
	cmd.Env = buildEnv
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	log.Printf("Command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// CopyCMakeIntegration copies the CMake integration to shareDir.
// Directories are created as needed.
func (i *CIFuzzBuilder) CopyCMakeIntegration() error {
	var err error
	err = i.Lock()
	if err != nil {
		return err
	}
	defer func() {
		err = i.Unlock()
		if err != nil {
			log.Printf("error: %v", err)
		}
	}()

	cmakeSrc := filepath.Join(i.projectDir, "tools", "cmake", "cifuzz")
	destDir := i.shareDir()
	opts := copy.Options{
		// Skip copying the replayer, which is a symlink on UNIX but checked out
		// by git as a file containing the relative path on Windows. It is
		// handled below.
		OnSymlink: func(string) copy.SymlinkAction {
			return copy.Skip
		},
	}
	err = copy.Copy(cmakeSrc, destDir, opts)
	if err != nil {
		return errors.WithStack(err)
	}

	// Copy the replayer, which is a symlink and thus may not have been copied
	// correctly on Windows.
	replayerSrc := filepath.Join(i.projectDir, "tools", "replayer", "src", "replayer.c")
	replayerDir := filepath.Join(destDir, "src")
	err = os.MkdirAll(replayerDir, 0755)
	if err != nil {
		return errors.WithStack(err)
	}
	err = copy.Copy(replayerSrc, filepath.Join(replayerDir, "replayer.c"))
	if err != nil {
		return errors.WithStack(err)
	}
	err = copy.Copy(replayerSrc, filepath.Join(replayerDir, "replayer.cpp"))
	if err != nil {
		return errors.WithStack(err)
	}
	// The same applies to the C++ version of the launcher and the dumper.
	launcherSrc := filepath.Join(i.projectDir, "tools", "cmake", "cifuzz", "src", "launcher.c")
	err = copy.Copy(launcherSrc, filepath.Join(destDir, "src", "launcher.cpp"))
	if err != nil {
		return errors.WithStack(err)
	}
	dumperSrc := filepath.Join(i.projectDir, "tools", "cmake", "cifuzz", "src", "dumper.c")
	err = copy.Copy(dumperSrc, filepath.Join(destDir, "src", "dumper.cpp"))
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (i *CIFuzzBuilder) CopySharedFolder() error {
	var err error
	err = i.Lock()
	if err != nil {
		return err
	}
	defer func() {
		err = i.Unlock()
		if err != nil {
			log.Printf("error: %v", err)
		}
	}()

	tasksSrc := filepath.Join(i.projectDir, "share")
	destDir := filepath.Join(i.shareDir(), "share")
	err = copy.Copy(tasksSrc, destDir)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func FindProjectDir() (string, error) {
	// Find the project root directory
	projectDir, err := os.Getwd()
	if err != nil {
		return "", errors.WithStack(err)
	}
	exists, err := fileutil.Exists(filepath.Join(projectDir, "go.mod"))
	if err != nil {
		return "", errors.WithStack(err)
	}
	for !exists {
		if filepath.Dir(projectDir) == projectDir {
			return "", errors.Errorf("Couldn't find project root directory")
		}
		projectDir = filepath.Dir(projectDir)
		exists, err = fileutil.Exists(filepath.Join(projectDir, "go.mod"))
		if err != nil {
			return "", errors.WithStack(err)
		}
	}
	return projectDir, nil
}

func CIFuzzExecutablePath(binDir string) string {
	path := filepath.Join(binDir, "cifuzz")
	if runtime.GOOS == "windows" {
		path += ".exe"
	}
	return path
}

func validateTargetDir(targetDir string) (string, error) {
	var err error

	if strings.HasPrefix(targetDir, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errors.WithStack(err)
		}
		targetDir = home + strings.TrimPrefix(targetDir, "~")
	}

	targetDir, err = filepath.Abs(targetDir)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return targetDir, nil
}
