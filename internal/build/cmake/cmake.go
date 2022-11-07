package cmake

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/fileutil"
)

// The CMake configuration (also called "build type") to use for fuzzing runs.
// See enable_fuzz_testing in tools/cmake/CIFuzz/share/CIFuzz/CIFuzzFunctions.cmake for the rationale for using this
// build type.
const cmakeBuildConfiguration = "RelWithDebInfo"

type ParallelOptions struct {
	Enabled bool
	NumJobs uint
}

type BuilderOptions struct {
	ProjectDir string
	Engine     string
	Sanitizers []string
	Parallel   ParallelOptions
	Stdout     io.Writer
	Stderr     io.Writer

	FindRuntimeDeps bool
}

func (opts *BuilderOptions) Validate() error {
	// Check that the project dir is set
	if opts.ProjectDir == "" {
		return errors.New("ProjectDir is not set")
	}
	// Check that the project dir exists and can be accessed
	_, err := os.Stat(opts.ProjectDir)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type Builder struct {
	*BuilderOptions
	env []string
}

func NewBuilder(opts *BuilderOptions) (*Builder, error) {
	err := opts.Validate()
	if err != nil {
		return nil, err
	}

	b := &Builder{BuilderOptions: opts}

	// Ensure that the build directory exists.
	err = os.MkdirAll(b.BuildDir(), 0755)
	if err != nil {
		return nil, err
	}

	b.env, err = build.CommonBuildEnv()
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (b *Builder) Opts() *BuilderOptions {
	return b.BuilderOptions
}

func (b *Builder) BuildDir() string {
	// Note: Invoking CMake on the same build directory with different cache
	// variables is a no-op. For this reason, we have to encode all choices made
	// for the cache variables below in the path to the build directory.
	// Currently, this includes the fuzzing engine and the choice of sanitizers.
	sanitizersSegment := strings.Join(b.Sanitizers, "+")
	if sanitizersSegment == "" {
		sanitizersSegment = "none"
	}
	return filepath.Join(
		b.ProjectDir,
		".cifuzz-build",
		b.Engine,
		sanitizersSegment,
	)
}

// Configure calls cmake to "Generate a project buildsystem" (that's the
// phrasing used by the CMake man page).
// Note: This is usually a no-op after the directory has been created once,
// even if cache variables change. However, if a previous invocation of this
// command failed during CMake generation and the command is run again, the
// build step would only result in a very unhelpful error message about
// missing Makefiles. By reinvoking CMake's configuration explicitly here,
// we either get a helpful error message or the build step will succeed if
// the user fixed the issue in the meantime.
func (b *Builder) Configure() error {
	cacheArgs := []string{
		"-DCMAKE_BUILD_TYPE=" + cmakeBuildConfiguration,
		"-DCIFUZZ_ENGINE=" + b.Engine,
		"-DCIFUZZ_SANITIZERS=" + strings.Join(b.Sanitizers, ";"),
		"-DCIFUZZ_TESTING:BOOL=ON",
	}
	if viper.GetBool("verbose") {
		cacheArgs = append(cacheArgs, "-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON")
	}
	if runtime.GOOS != "windows" {
		// Use relative paths in RPATH/RUNPATH so that binaries from the
		// build directory can find their shared libraries even when
		// packaged into an artifact.
		// On Windows, where there is no RPATH, there are two ways the user or
		// we can handle this:
		// 1. Use the TARGET_RUNTIME_DLLS generator expression introduced in
		//    CMake 3.21 to copy all DLLs into the directory of the executable
		//    in a post-build action.
		// 2. Add all library directories to PATH.
		cacheArgs = append(cacheArgs, "-DCMAKE_BUILD_RPATH_USE_ORIGIN:BOOL=ON")
	}

	cmd := exec.Command("cmake", append(cacheArgs, b.ProjectDir)...)
	// Redirect the build command's stdout to stderr to only have
	// reports printed to stdout
	cmd.Stdout = b.Stderr
	cmd.Stderr = b.Stderr
	cmd.Env = b.env
	cmd.Dir = b.BuildDir()
	log.Debugf("Working directory: %s", cmd.Dir)
	log.Debugf("Command: %s", cmd.String())
	err := cmd.Run()
	if err != nil {
		// It's expected that cmake might fail due to user configuration,
		// so we print the error without the stack trace.
		err = cmdutils.WrapExecError(err, cmd)
		log.Error(err)
		return cmdutils.ErrSilent
	}
	return nil
}

// Build builds the specified fuzz tests with CMake
func (b *Builder) Build(fuzzTests []string) (map[string]*build.Result, error) {
	buildDir, err := fileutil.CanonicalPath(b.BuildDir())
	if err != nil {
		return nil, err
	}

	flags := append([]string{
		"--build", buildDir,
		"--config", cmakeBuildConfiguration,
		"--target"}, fuzzTests...)

	if b.Parallel.Enabled {
		flags = append(flags, "--parallel")
		if b.Parallel.NumJobs != 0 {
			flags = append(flags, fmt.Sprint(b.Parallel.NumJobs))
		}
	}

	cmd := exec.Command("cmake", flags...)
	// Redirect the build command's stdout to stderr to only have
	// reports printed to stdout
	cmd.Stdout = b.Stderr
	cmd.Stderr = b.Stderr
	cmd.Env = b.env
	log.Debugf("Command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		// It's expected that cmake might fail due to user configuration,
		// so we print the error without the stack trace.
		err = cmdutils.WrapExecError(err, cmd)
		log.Error(err)
		return nil, cmdutils.ErrSilent
	}

	results := make(map[string]*build.Result)
	for _, fuzzTest := range fuzzTests {
		executable, err := b.findFuzzTestExecutable(fuzzTest)
		if err != nil {
			return nil, err
		}
		seedCorpus, err := b.findFuzzTestSeedCorpus(fuzzTest)
		if err != nil {
			return nil, err
		}
		var runtimeDeps []string
		if b.FindRuntimeDeps {
			runtimeDeps, err = b.getRuntimeDeps(fuzzTest)
			if err != nil {
				return nil, err
			}
		}
		generatedCorpus := filepath.Join(b.ProjectDir, ".cifuzz-corpus", fuzzTest)
		results[fuzzTest] = &build.Result{
			Name:            fuzzTest,
			Executable:      executable,
			GeneratedCorpus: generatedCorpus,
			SeedCorpus:      seedCorpus,
			BuildDir:        buildDir,
			ProjectDir:      b.ProjectDir,
			Engine:          b.Engine,
			Sanitizers:      b.Sanitizers,
			RuntimeDeps:     runtimeDeps,
		}
	}

	return results, nil
}

// findFuzzTestExecutable uses the info files emitted by the CMake integration
// in the configure step to look up the canonical path of a fuzz test's
// executable.
func (b *Builder) findFuzzTestExecutable(fuzzTest string) (string, error) {
	return b.readInfoFileAsPath(fuzzTest, "executable")
}

// findFuzzTestSeedCorpus uses the info files emitted by the CMake integration
// in the configure step to look up the canonical path of a fuzz test's
// seed corpus directory.
func (b *Builder) findFuzzTestSeedCorpus(fuzzTest string) (string, error) {
	return b.readInfoFileAsPath(fuzzTest, "seed_corpus")
}

// ListFuzzTests lists all fuzz tests defined in the CMake project after
// Configure has been run.
func (b *Builder) ListFuzzTests() ([]string, error) {
	fuzzTestsDir, err := b.fuzzTestsInfoDir()
	if err != nil {
		return nil, err
	}
	fuzzTestEntries, err := os.ReadDir(fuzzTestsDir)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var fuzzTests []string
	for _, entry := range fuzzTestEntries {
		fuzzTests = append(fuzzTests, entry.Name())
	}
	return fuzzTests, nil
}

// getRuntimeDeps returns the canonical paths of all (transitive) runtime
// dependencies of the given fuzz test. It prints a warning if any dependency
// couldn't be resolved or resolves to more than one file.
func (b *Builder) getRuntimeDeps(fuzzTest string) ([]string, error) {
	cmd := exec.Command(
		"cmake",
		"--install",
		b.BuildDir(),
		"--config", cmakeBuildConfiguration,
		"--component", "cifuzz_internal_deps_"+fuzzTest,
	)
	stdout, err := cmd.Output()
	if err != nil {
		// It's expected that cmake might fail due to user configuration,
		// so we print the error without the stack trace.
		err = cmdutils.WrapExecError(err, cmd)
		log.Error(err)
		return nil, cmdutils.ErrSilent
	}

	var resolvedDeps []string
	var unresolvedDeps []string
	var conflictingDeps []string
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		// Typical lines in the output of the install command look like this:
		//
		// <arbitrary CMake output>
		// -- CIFUZZ RESOLVED /usr/lib/system.so
		// -- CIFUZZ RESOLVED /home/user/git/project/build/lib/bar.so
		// -- CIFUZZ UNRESOLVED not_found.so

		// Skip over CMake output.
		if !strings.HasPrefix(line, "-- CIFUZZ ") {
			continue
		}
		statusAndDep := strings.TrimPrefix(line, "-- CIFUZZ ")
		endOfStatus := strings.Index(statusAndDep, " ")
		if endOfStatus == -1 {
			return nil, errors.Errorf("invalid runtime dep line: %s", line)
		}
		status := statusAndDep[:endOfStatus]
		dep := statusAndDep[endOfStatus+1:]
		dep, err = fileutil.CanonicalPath(dep)
		if err != nil {
			return nil, err
		}

		switch status {
		case "UNRESOLVED":
			unresolvedDeps = append(unresolvedDeps, dep)
		case "CONFLICTING":
			conflictingDeps = append(conflictingDeps, dep)
		case "RESOLVED":
			resolvedDeps = append(resolvedDeps, dep)
		default:
			return nil, errors.Errorf("invalid status '%s' in runtime dep line: %s", status, line)
		}
	}

	if len(unresolvedDeps) > 0 || len(conflictingDeps) > 0 {
		var warning strings.Builder
		if len(unresolvedDeps) > 0 {
			warning.WriteString(
				fmt.Sprintf("The following shared library dependencies of %s could not be resolved:\n", fuzzTest))
			for _, unresolvedDep := range unresolvedDeps {
				warning.WriteString(fmt.Sprintf("  %s\n", unresolvedDep))
			}
		}
		if len(conflictingDeps) > 0 {
			warning.WriteString(
				fmt.Sprintf("The following shared library dependencies of %s could not be resolved unambiguously:\n", fuzzTest))
			for _, conflictingDep := range conflictingDeps {
				warning.WriteString(fmt.Sprintf("  %s\n", conflictingDep))
			}
		}
		warning.WriteString("The archive may be incomplete.\n")
		log.Warn(warning.String())
	}

	return resolvedDeps, nil
}

// readInfoFileAsPath returns the contents of the CMake-generated info file of type kind for the given fuzz test,
// interpreted as a path. All symlinks are followed.
func (b *Builder) readInfoFileAsPath(fuzzTest string, kind string) (string, error) {
	fuzzTestsInfoDir, err := b.fuzzTestsInfoDir()
	if err != nil {
		return "", err
	}
	infoFile := filepath.Join(fuzzTestsInfoDir, fuzzTest, kind)
	content, err := os.ReadFile(infoFile)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return fileutil.CanonicalPath(string(content))
}

func (b *Builder) fuzzTestsInfoDir() (string, error) {
	// The path to the info file for single-configuration CMake generators (e.g. Makefiles).
	fuzzTestsDir := filepath.Join(b.BuildDir(), ".cifuzz", "fuzz_tests")
	if fileutil.IsDir(fuzzTestsDir) {
		return fuzzTestsDir, nil
	}
	// The path to the info file for multi-configuration CMake generators (e.g. MSBuild).
	fuzzTestsDir = filepath.Join(b.BuildDir(), cmakeBuildConfiguration, ".cifuzz", "fuzz_tests")
	if fileutil.IsDir(fuzzTestsDir) {
		return fuzzTestsDir, nil
	}
	return "", os.ErrNotExist
}
