package cmake

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"

	builderPkg "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/pkg/artifact"
	"code-intelligence.com/cifuzz/pkg/parser/libfuzzer/stacktrace"
	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

func TestIntegration_CMake_InitCreateRunCoverageBundle(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	testutil.RegisterTestDepOnCIFuzz()

	// Create installation builder
	installDir := testutil.InstallCifuzzInTemp(t)
	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))
	err := os.Setenv("CMAKE_PREFIX_PATH", installDir)
	require.NoError(t, err)

	// Copy testdata
	dir := testutil.CopyTestdataDir(t, "cmake")
	defer fileutil.Cleanup(dir)
	t.Logf("executing cmake integration test in %s", dir)

	// Execute the root command
	testutil.RunCommand(t, dir, cifuzz, nil)

	// Execute the init command
	initOutput := testutil.RunCommand(t, dir, cifuzz, []string{"init"})
	testutil.AddLinesToFileAtBreakPoint(t, filepath.Join(dir, "CMakeLists.txt"), initOutput, "add_subdirectory", false)

	// Execute the create command
	outputPath := filepath.Join("src", "parser", "parser_fuzz_test.cpp")
	createOutput := testutil.RunCommand(t, dir, cifuzz, []string{"create", "cpp", "--output", outputPath})

	// Check that the fuzz test was created in the correct directory
	fuzzTestPath := filepath.Join(dir, outputPath)
	require.FileExists(t, fuzzTestPath)

	// Append the lines to CMakeLists.txt
	f, err := os.OpenFile(filepath.Join(filepath.Dir(fuzzTestPath), "CMakeLists.txt"), os.O_APPEND|os.O_WRONLY, 0600)
	defer f.Close()
	require.NoError(t, err)
	for _, s := range createOutput {
		_, err = f.WriteString(s + "\n")
		require.NoError(t, err)
	}

	// Check that the findings command doesn't list any findings yet
	findings := testutil.GetFindings(t, cifuzz, dir)
	require.Empty(t, findings)

	// Run the (empty) fuzz test
	runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
		expectedOutput:               regexp.MustCompile(`^paths: \d+`),
		terminateAfterExpectedOutput: true,
	})

	// Make the fuzz test call a function. Before we do that, we sleep
	// for one second, to avoid make implementations which only look at
	// the full seconds of the timestamp to not rebuild the target, see
	// https://www.gnu.org/software/autoconf/manual/autoconf-2.63/html_node/Timestamps-and-Make.html
	time.Sleep(time.Second)
	modifyFuzzTestToCallFunction(t, fuzzTestPath)
	// Run the fuzz test
	runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
		expectedOutput: regexp.MustCompile(`^==\d*==ERROR: AddressSanitizer: heap-use-after-free`),
	})

	// Check that the findings command lists the finding
	findings = testutil.GetFindings(t, cifuzz, dir)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0].Details, "heap-use-after-free")
	// TODO: This check currently fails on macOS because there
	// llvm-symbolizer doesn't read debug info from object files.
	// See https://github.com/google/sanitizers/issues/207#issuecomment-136495556
	if runtime.GOOS != "darwin" {
		expectedStackTrace := []*stacktrace.StackFrame{
			{
				SourceFile:  "src/parser/parser.cpp",
				Line:        19,
				Column:      14,
				FrameNumber: 0,
				Function:    "parse",
			},
			{
				SourceFile:  "src/parser/parser_fuzz_test.cpp",
				Line:        20,
				Column:      3,
				FrameNumber: 1,
				Function:    "LLVMFuzzerTestOneInputNoReturn",
			},
		}
		if runtime.GOOS == "windows" {
			// On Windows, the column is not printed
			for i := range expectedStackTrace {
				expectedStackTrace[i].Column = 0
			}
		}

		require.Equal(t, expectedStackTrace, findings[0].StackTrace)
	}

	// Check that options set via the config file are respected
	configFileContent := `use-sandbox: false`
	err = os.WriteFile(filepath.Join(dir, "cifuzz.yaml"), []byte(configFileContent), 0644)
	require.NoError(t, err)
	// When minijail is used, the artifact prefix is set to the minijail
	// output path
	runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
		expectedOutput: regexp.MustCompile(`artifact_prefix='./'`),
	})

	if runtime.GOOS == "linux" {
		// Check that command-line flags take precedence over config file
		// settings (only on Linux because we only support Minijail on
		// Linux).
		runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
			expectedOutput: regexp.MustCompile(`minijail`),
			args:           []string{"--use-sandbox=true"},
		})
	}
	// Clear cifuzz.yml so that subsequent tests run with defaults (e.g. sandboxing).
	err = os.WriteFile(filepath.Join(dir, "cifuzz.yaml"), nil, 0644)
	require.NoError(t, err)

	// Check that ASAN_OPTIONS can be set
	env, err := envutil.Setenv(os.Environ(), "ASAN_OPTIONS", "print_stats=1:atexit=1")
	require.NoError(t, err)
	runFuzzer(t, cifuzz, dir, &runFuzzerOptions{
		expectedOutput:               regexp.MustCompile(`Stats:`),
		terminateAfterExpectedOutput: false,
		env:                          env,
	})

	// Building with coverage instrumentation doesn't work on Windows yet
	if runtime.GOOS != "windows" {
		// Produce a coverage report for parser_fuzz_test
		createHtmlCoverageReport(t, cifuzz, dir)
		// Produces a coverage report for crashing_fuzz_test
		createAndVerifyLcovCoverageReport(t, cifuzz, dir)
	}

	// Run cifuzz bundle and verify the contents of the archive.
	testBundle(t, dir, cifuzz)

	// The remote-run command is currently only supported on Linux
	if runtime.GOOS == "linux" {
		testRemoteRun(t, dir, cifuzz)
	}
}

type runFuzzerOptions struct {
	expectedOutput               *regexp.Regexp
	terminateAfterExpectedOutput bool
	env                          []string
	args                         []string
}

func runFuzzer(t *testing.T, cifuzz string, dir string, opts *runFuzzerOptions) {
	t.Helper()

	if opts.env == nil {
		opts.env = os.Environ()
	}

	runCtx, closeRunCtx := context.WithCancel(context.Background())
	defer closeRunCtx()
	args := append([]string{"run", "-v", "parser_fuzz_test",
		"--no-notifications",
		"--engine-arg=-seed=1",
		"--engine-arg=-runs=1000000"},
		opts.args...)
	cmd := executil.CommandContext(
		runCtx,
		cifuzz,
		args...,
	)
	cmd.Dir = dir
	cmd.Env = opts.env
	stdoutPipe, err := cmd.StdoutTeePipe(os.Stdout)
	require.NoError(t, err)
	stderrPipe, err := cmd.StderrTeePipe(os.Stderr)
	require.NoError(t, err)

	// Terminate the cifuzz process when we receive a termination signal
	// (else the test won't stop). An alternative would be to run the
	// command in the foreground, via syscall.SysProcAttr.Foreground,
	// but that's not supported on Windows.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		s := <-sigs
		t.Logf("Received %s", s.String())
		err = cmd.TerminateProcessGroup()
		require.NoError(t, err)
	}()

	t.Logf("Command: %s", cmd.String())
	err = cmd.Start()
	require.NoError(t, err)

	waitErrCh := make(chan error)
	// Wait for the command to exit in a go routine, so that below
	// we can cancel waiting when the context is done
	go func() {
		waitErrCh <- cmd.Wait()
	}()

	// Check that the output contains the expected output
	seenExpectedOutput := &atomic.Value{}
	seenExpectedOutput.Store(false)

	routines := errgroup.Group{}
	routines.Go(func() error {
		// cifuzz progress messages go to stdout.
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			if opts.expectedOutput.MatchString(scanner.Text()) {
				seenExpectedOutput.Store(true)
				if opts.terminateAfterExpectedOutput {
					err = cmd.TerminateProcessGroup()
					require.NoError(t, err)
				}
			}
		}
		err = stdoutPipe.Close()
		require.NoError(t, err)
		return nil
	})

	routines.Go(func() error {
		// Fuzzer output goes to stderr.
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			if opts.expectedOutput.MatchString(scanner.Text()) {
				seenExpectedOutput.Store(true)
				if opts.terminateAfterExpectedOutput {
					err = cmd.TerminateProcessGroup()
					require.NoError(t, err)
				}
			}
		}
		err = stderrPipe.Close()
		require.NoError(t, err)
		return nil
	})

	select {
	case waitErr := <-waitErrCh:

		err = routines.Wait()
		require.NoError(t, err)

		seen := seenExpectedOutput.Load().(bool)
		if seen && opts.terminateAfterExpectedOutput && executil.IsTerminatedExitErr(waitErr) {
			return
		}
		require.NoError(t, waitErr)
	case <-runCtx.Done():
		require.NoError(t, runCtx.Err())
	}

	seen := seenExpectedOutput.Load().(bool)
	require.True(t, seen, "Did not see %q in fuzzer output", opts.expectedOutput.String())
}

func createHtmlCoverageReport(t *testing.T, cifuzz string, dir string) {
	t.Helper()

	cmd := executil.Command(cifuzz, "coverage", "-v",
		"--output", "parser_fuzz_test.coverage.html",
		"parser_fuzz_test")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err)

	// Check that the coverage report was created
	reportPath := filepath.Join(dir, "parser_fuzz_test.coverage.html")
	require.FileExists(t, reportPath)

	// Check that the coverage report contains coverage for the
	// parser.cpp source file, but not for our headers.
	reportBytes, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	report := string(reportBytes)
	require.Contains(t, report, "parser.cpp")
	require.NotContains(t, report, "include/cifuzz")
}

func createAndVerifyLcovCoverageReport(t *testing.T, cifuzz string, dir string) {
	t.Helper()

	reportPath := filepath.Join(dir, "crashing_fuzz_test.lcov")

	cmd := executil.Command(cifuzz, "coverage", "-v",
		"--format=lcov",
		"--output", reportPath,
		"crashing_fuzz_test")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err)

	// Check that the coverage report was created
	require.FileExists(t, reportPath)

	// Read the report and extract all uncovered lines in the fuzz test source file.
	reportBytes, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	lcov := bufio.NewScanner(bytes.NewBuffer(reportBytes))
	isFuzzTestSource := false
	var uncoveredLines []uint
	for lcov.Scan() {
		line := lcov.Text()

		if strings.HasPrefix(line, "SF:") {
			if strings.HasSuffix(line, "/coverage/crashing_fuzz_test.cpp") {
				isFuzzTestSource = true
			} else {
				isFuzzTestSource = false
				assert.Fail(t, "Unexpected source file: "+line)
			}
		}

		if !isFuzzTestSource || !strings.HasPrefix(line, "DA:") {
			continue
		}
		split := strings.Split(strings.TrimPrefix(line, "DA:"), ",")
		require.Len(t, split, 2)
		if split[1] == "0" {
			lineNo, err := strconv.Atoi(split[0])
			require.NoError(t, err)
			uncoveredLines = append(uncoveredLines, uint(lineNo))
		}
	}

	assert.Subset(t, []uint{
		// Lines after the three crashes. Whether these are covered depends on implementation details of the coverage
		// instrumentation, so we conservatively assume they aren't covered.
		21, 31, 41},
		uncoveredLines)
}

func modifyFuzzTestToCallFunction(t *testing.T, fuzzTestPath string) {
	// Modify the fuzz test stub created by `cifuzz create` to actually
	// call a function.

	f, err := os.OpenFile(fuzzTestPath, os.O_RDWR, 0700)
	require.NoError(t, err)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	// At the top of the file we add the required headers
	lines := []string{`#include "parser.h"`}
	var seenBeginningOfFuzzTestFunc bool
	var addedFunctionCall bool
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "FUZZ_TEST(") {
			seenBeginningOfFuzzTestFunc = true
		}
		// Insert the function call at the end of the FUZZ_TEST
		// function, right above the "}".
		if seenBeginningOfFuzzTestFunc && strings.HasPrefix(scanner.Text(), "}") {
			lines = append(lines, "  parse(std::string(reinterpret_cast<const char *>(data), size));")
			addedFunctionCall = true
		}
		lines = append(lines, scanner.Text())
	}
	require.NoError(t, scanner.Err())
	require.True(t, addedFunctionCall)

	// Write the new content of the fuzz test back to file
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	_, err = f.WriteString(strings.Join(lines, "\n"))
	require.NoError(t, err)

	// Add dependency on parser lib to CMakeLists.txt
	cmakeLists := filepath.Join(filepath.Dir(fuzzTestPath), "CMakeLists.txt")
	f, err = os.OpenFile(cmakeLists, os.O_APPEND|os.O_WRONLY, 0700)
	require.NoError(t, err)
	defer f.Close()
	_, err = f.WriteString("target_link_libraries(parser_fuzz_test PRIVATE parser)\n")
	require.NoError(t, err)
}

func testBundle(t *testing.T, dir string, cifuzz string) {
	tempDir, err := os.MkdirTemp("", "cifuzz-archive-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)
	bundlePath := filepath.Join(tempDir, "parser_fuzz_test.tar.gz")
	defer fileutil.Cleanup(bundlePath)

	// Create a dictionary
	dictPath := filepath.Join(tempDir, "some_dict")
	err = os.WriteFile(dictPath, []byte("test-dictionary-content"), 0600)
	require.NoError(t, err)

	// Create a seed corpus directory with an empty seed
	seedCorpusDir, err := os.MkdirTemp(tempDir, "seeds-")
	require.NoError(t, err)
	err = fileutil.Touch(filepath.Join(seedCorpusDir, "empty"))
	require.NoError(t, err)

	// Bundle all fuzz tests into an archive.
	cmd := executil.Command(cifuzz, "bundle",
		"-o", bundlePath,
		"--dict", dictPath,
		// Only run the fuzzer on the empty input.
		"--engine-arg", "-runs=0",
		"--fuzz-test-arg", "arg3",
		"--fuzz-test-arg", "arg4",
		"--seed-corpus", seedCorpusDir,
		"--timeout", "100m",
		"--branch", "my-branch",
		"--commit", "123456abcdef",
		"--env", "FOO=foo",
		// This should be set to the value from the local environment,
		// which we set to "bar" below
		"--env", "BAR",
		// This should be ignored because it's not set in the local
		// environment
		"--env", "NO_SUCH_VARIABLE",
		"--verbose",
	)
	cmd.Dir = dir
	cmd.Env, err = envutil.Setenv(os.Environ(), "BAR", "bar")
	require.NoError(t, err)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	require.NoError(t, err)
	require.FileExists(t, bundlePath)

	// Extract the archive into a new temporary directory.
	archiveDir, err := os.MkdirTemp("", "cifuzz-extracted-archive-*")
	require.NoError(t, err)
	archiveFile, err := os.Open(bundlePath)
	require.NoError(t, err)
	err = artifact.ExtractArchiveForTestsOnly(archiveFile, archiveDir)
	require.NoError(t, err)

	// Read the fuzzer path from the YAML.
	metadataPath := filepath.Join(archiveDir, "cifuzz.yaml")
	require.FileExists(t, metadataPath)
	metadataYaml, err := os.ReadFile(metadataPath)
	require.NoError(t, err)

	metadata := &artifact.Metadata{}
	err = yaml.Unmarshal(metadataYaml, metadata)
	require.NoError(t, err)

	// Verify code revision given by `--branch` and `--commit-sha` flags
	assert.Equal(t, "my-branch", metadata.CodeRevision.Git.Branch)
	assert.Equal(t, "123456abcdef", metadata.CodeRevision.Git.Commit)

	// Verify that the metadata contain the engine args and fuzz test args
	assert.Equal(t, []string{"-runs=0"}, metadata.Fuzzers[0].EngineOptions.Flags)
	assert.Equal(t, []string{"arg3", "arg4"}, metadata.Fuzzers[0].FuzzTestArgs)

	// Verify the metadata contains the env vars
	require.Equal(t, []string{"FOO=foo", "BAR=bar", "NO_CIFUZZ=1"}, metadata.Fuzzers[0].EngineOptions.Env)

	var parserFuzzer *artifact.Fuzzer
	var parserCoverage *artifact.Fuzzer
	for _, fuzzer := range metadata.Fuzzers {
		if fuzzer.Target == "parser_fuzz_test" {
			if fuzzer.Engine == "LIBFUZZER" {
				parserFuzzer = fuzzer
			} else if fuzzer.Engine == "LLVM_COV" {
				parserCoverage = fuzzer
			}
		}
	}

	require.NotNil(t, parserFuzzer)
	fuzzerPath := filepath.Join(archiveDir, parserFuzzer.Path)
	require.FileExists(t, fuzzerPath)

	// Run the fuzzer on the empty input to verify that it finds all its runtime dependencies.
	cmd = executil.Command(fuzzerPath, parserFuzzer.EngineOptions.Flags...)
	cmd.Dir = filepath.Join(archiveDir, "work_dir")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), parserFuzzer.EngineOptions.Env...)
	err = cmd.Run()
	assert.NoError(t, err)

	// Verify that the dictionary has been packaged with the fuzzer.
	dictPath = filepath.Join(archiveDir, parserFuzzer.Dictionary)
	require.FileExists(t, dictPath)
	content, err := os.ReadFile(dictPath)
	require.NoError(t, err)
	assert.Equal(t, "test-dictionary-content", string(content))

	// Verify that the seed corpus has been packaged with the fuzzer.
	seedCorpusPath := filepath.Join(archiveDir, parserFuzzer.Seeds)
	require.DirExists(t, seedCorpusPath)
	assert.FileExists(t, filepath.Join(seedCorpusPath, "parser_fuzz_test_inputs", "some_seed"))
	// Check that the empty seed from the user-specified seed corpus
	// was copied into the archive
	assert.FileExists(t, filepath.Join(seedCorpusPath, filepath.Base(seedCorpusDir), "empty"))

	// Verify that the maximum runtime has been set
	assert.Equal(t, uint(6000), parserFuzzer.MaxRunTime)

	if runtime.GOOS == "windows" {
		// There are no coverage builds on Windows.
		return
	}
	// Verify that a coverage build has been added to the archive.
	require.NotNil(t, parserCoverage)
	fuzzerPath = filepath.Join(archiveDir, parserCoverage.Path)
	require.FileExists(t, fuzzerPath)

	// Run the coverage build, which uses the replayer, on the seed corpus and verify that it creates a coverage
	// profile.
	coverageProfile := filepath.Join(archiveDir, "profile.lcov")
	cmd = executil.Command(fuzzerPath, append(parserCoverage.EngineOptions.Flags, seedCorpusPath)...)
	cmd.Dir = filepath.Join(archiveDir, "work_dir")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "LLVM_PROFILE_FILE="+coverageProfile)
	cmd.Env = append(cmd.Env, parserCoverage.EngineOptions.Env...)
	err = cmd.Run()
	assert.NoError(t, err)
	assert.FileExists(t, coverageProfile)

	if runtime.GOOS == "linux" {
		// Try to use the artifacts to start a remote run on a mock server
		projectName := "test-project"
		artifactsName := "test-artifacts-123"
		token := "test-token"
		server := startMockServer(t, projectName, artifactsName)
		cmd = executil.Command(cifuzz, "remote-run",
			"--bundle", bundlePath,
			"--project", projectName,
			"--server", server.address,
		)
		cmd.Env, err = envutil.Setenv(os.Environ(), "CIFUZZ_API_TOKEN", token)
		require.NoError(t, err)
		cmd.Dir = dir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		t.Logf("Command: %s", cmd.String())
		err = cmd.Run()
		require.NoError(t, err)
		require.FileExists(t, bundlePath)
		require.True(t, server.artifactsUploaded)
		require.True(t, server.runStarted)
	}
}

func testRemoteRun(t *testing.T, dir string, cifuzz string) {
	projectName := "test-project"
	artifactsName := "test-artifacts-123"
	token := "test-token"

	// Start a mock server to handle our requests
	server := startMockServer(t, projectName, artifactsName)

	tempDir, err := os.MkdirTemp("", "cifuzz-archive-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)

	// Create a dictionary
	dictPath := filepath.Join(tempDir, "some_dict")
	err = os.WriteFile(dictPath, []byte("test-dictionary-content"), 0600)
	require.NoError(t, err)

	// Create a seed corpus directory with an empty seed
	seedCorpusDir, err := os.MkdirTemp(tempDir, "seeds-")
	require.NoError(t, err)
	err = fileutil.Touch(filepath.Join(seedCorpusDir, "empty"))
	require.NoError(t, err)

	// Try to start a remote run on our mock server
	cmd := executil.Command(cifuzz, "remote-run",
		"--dict", dictPath,
		"--engine-arg", "arg1",
		"--engine-arg", "arg2",
		"--fuzz-test-arg", "arg3",
		"--fuzz-test-arg", "arg4",
		"--seed-corpus", seedCorpusDir,
		"--timeout", "100m",
		"--project", projectName,
		"--server", server.address,
	)
	cmd.Env, err = envutil.Setenv(os.Environ(), "CIFUZZ_API_TOKEN", token)
	require.NoError(t, err)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	t.Logf("Command: %s", cmd.String())
	err = cmd.Run()
	require.NoError(t, err)

	require.True(t, server.artifactsUploaded)
	require.True(t, server.runStarted)
}

type mockServer struct {
	address           string
	artifactsUploaded bool
	runStarted        bool
}

func startMockServer(t *testing.T, projectName, artifactsName string) *mockServer {
	server := &mockServer{}

	handleUpload := func(w http.ResponseWriter, req *http.Request) {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		_, err = fmt.Fprintf(w, `{"display-name": "test-artifacts", "resource-name": "%s"}`, artifactsName)
		require.NoError(t, err)
		server.artifactsUploaded = true
	}

	handleStartRun := func(w http.ResponseWriter, req *http.Request) {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		_, err = fmt.Fprintf(w, `{"name": "test-campaign-run-123"}`)
		require.NoError(t, err)
		server.runStarted = true
	}

	handleDefault := func(w http.ResponseWriter, req *http.Request) {
		require.Fail(t, "Unexpected request", stringutil.PrettyString(req))
	}

	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/v2/projects/%s/artifacts/import", projectName), handleUpload)
	mux.HandleFunc(fmt.Sprintf("/v1/%s:run", artifactsName), handleStartRun)
	mux.HandleFunc("/", handleDefault)

	listener, err := net.Listen("tcp4", ":0")
	require.NoError(t, err)

	server.address = fmt.Sprintf("http://127.0.0.1:%d", listener.Addr().(*net.TCPAddr).Port)

	go func() {
		err = http.Serve(listener, mux)
		require.NoError(t, err)
	}()

	return server
}
