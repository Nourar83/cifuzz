package shared

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mattn/go-zglob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"code-intelligence.com/cifuzz/internal/bundler/archive"
	"code-intelligence.com/cifuzz/util/archiveutil"
	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestBundleLibFuzzer(t *testing.T, dir string, cifuzz string, args ...string) {
	t.Helper()

	// Make the bundle command not fail on unsupported platforms to be
	// able to test it on all platforms
	err := os.Setenv("CIFUZZ_BUNDLE_ON_UNSUPPORTED_PLATFORMS", "1")
	require.NoError(t, err)

	tempDir, err := os.MkdirTemp("", "cifuzz-archive-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)
	bundlePath := filepath.Join(tempDir, "fuzz_tests.tar.gz")
	t.Logf("creating test bundle in %s", tempDir)

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
	defaultArgs := []string{
		"bundle",
		"-o", bundlePath,
		"--dict", dictPath,
		// Only run the fuzzer on the empty input.
		"--engine-arg", "-runs=0",
		"--seed-corpus", seedCorpusDir,
		"--timeout", "100m",
		"--branch", "my-branch",
		"--commit", "123456abcdef",
		"--docker-image", "my-image",
		"--env", "FOO=foo",
		// This should be set to the value from the local environment,
		// which we set to "bar" below
		"--env", "BAR",
		// This should be ignored because it's not set in the local
		// environment
		"--env", "NO_SUCH_VARIABLE",
		"--verbose",
	}
	args = append(defaultArgs, args...)
	metadata, archiveDir := TestRunBundle(t, dir, cifuzz, bundlePath, args...)
	defer fileutil.Cleanup(archiveDir)

	// Verify code revision given by `--branch` and `--commit-sha` flags
	assert.Equal(t, "my-branch", metadata.CodeRevision.Git.Branch)
	assert.Equal(t, "123456abcdef", metadata.CodeRevision.Git.Commit)

	// Verify that the metadata contain the engine flags
	assert.Equal(t, []string{"-runs=0"}, metadata.Fuzzers[0].EngineOptions.Flags)

	// Verify that the metadata contains the Docker image
	assert.Equal(t, "my-image", metadata.RunEnvironment.Docker)

	// Verify the metadata contains the env vars
	require.Equal(t, []string{"FOO=foo", "BAR=bar", "NO_CIFUZZ=1"}, metadata.Fuzzers[0].EngineOptions.Env)

	var fuzzerMetadata *archive.Fuzzer
	var coverageMetadata *archive.Fuzzer
	for _, fuzzer := range metadata.Fuzzers {
		if fuzzer.Engine == "LIBFUZZER" {
			fuzzerMetadata = fuzzer
		} else if fuzzer.Engine == "LLVM_COV" {
			coverageMetadata = fuzzer
		}
	}

	require.NotNil(t, fuzzerMetadata)
	fuzzerPath := filepath.Join(archiveDir, fuzzerMetadata.Path)
	require.FileExists(t, fuzzerPath)

	// Run the fuzzer on the empty input to verify that it finds all its runtime dependencies.
	cmd := executil.Command(fuzzerPath, fuzzerMetadata.EngineOptions.Flags...)
	cmd.Dir = filepath.Join(archiveDir, "work_dir")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), fuzzerMetadata.EngineOptions.Env...)
	err = cmd.Run()
	assert.NoError(t, err)

	// Verify that the dictionary has been packaged with the fuzzer.
	dictPath = filepath.Join(archiveDir, fuzzerMetadata.Dictionary)
	require.FileExists(t, dictPath)
	content, err := os.ReadFile(dictPath)
	require.NoError(t, err)
	assert.Equal(t, "test-dictionary-content", string(content))

	// Verify that the seed corpus has been packaged with the fuzzer.
	seedCorpusPath := filepath.Join(archiveDir, fuzzerMetadata.Seeds)
	require.DirExists(t, seedCorpusPath)
	pattern := filepath.Join(seedCorpusPath, "**", "*some_seed")
	matches, err := zglob.Glob(pattern)
	require.NoError(t, err)
	assert.NotEmpty(t, matches, "seed not found: %s", pattern)
	// Check that the empty seed from the user-specified seed corpus
	// was copied into the archive
	assert.FileExists(t, filepath.Join(seedCorpusPath, filepath.Base(seedCorpusDir), "empty"))

	// Verify that the maximum runtime has been set
	assert.Equal(t, uint(6000), fuzzerMetadata.MaxRunTime)

	if runtime.GOOS == "windows" {
		// There are no coverage builds on Windows.
		return
	}
	// Verify that a coverage build has been added to the archive.
	require.NotNil(t, coverageMetadata)
	fuzzerPath = filepath.Join(archiveDir, coverageMetadata.Path)
	require.FileExists(t, fuzzerPath)

	// Run the coverage build on the seed corpus and verify that it
	// creates a coverage profile.
	coverageProfile := filepath.Join(archiveDir, "profile.lcov")
	cmd = executil.Command(fuzzerPath, append(coverageMetadata.EngineOptions.Flags, seedCorpusPath)...)
	cmd.Dir = filepath.Join(archiveDir, "work_dir")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "LLVM_PROFILE_FILE="+coverageProfile)
	cmd.Env = append(cmd.Env, coverageMetadata.EngineOptions.Env...)
	t.Logf("Command: %s", cmd.String())
	err = cmd.Run()
	assert.NoError(t, err)
	assert.FileExists(t, coverageProfile)

	if runtime.GOOS == "linux" {
		// Try to use the artifacts to start a remote run on a mock server
		projectName := "test-project"
		artifactsName := "test-artifacts-123"
		token := "test-token"
		server := StartMockServer(t, projectName, artifactsName)
		cmd = executil.Command(cifuzz, "remote-run",
			"--bundle", bundlePath,
			"--project", projectName,
			"--server", server.Address,
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
		require.True(t, server.ArtifactsUploaded)
		require.True(t, server.RunStarted)
	}
}

func TestBundleMaven(t *testing.T, dir string, cifuzz string, args ...string) {
	tempDir, err := os.MkdirTemp("", "cifuzz-archive-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)
	bundlePath := filepath.Join(tempDir, "fuzz_tests.tar.gz")
	t.Logf("creating test bundle in %s", tempDir)

	// Create a dictionary
	dictPath := filepath.Join(tempDir, "some_dict")
	err = os.WriteFile(dictPath, []byte("test-dictionary-content"), 0600)
	require.NoError(t, err)

	// Create a seed corpus directory with an empty seed
	seedCorpusDir, err := os.MkdirTemp(tempDir, "seeds-")
	require.NoError(t, err)
	err = fileutil.Touch(filepath.Join(seedCorpusDir, "empty"))
	require.NoError(t, err)

	defaultArgs := []string{
		"bundle",
		"-o", bundlePath,
		"--dict", dictPath,
		"--seed-corpus", seedCorpusDir,
		"--timeout", "100m",
		"--branch", "my-branch",
		"--commit", "123456abcdef",
		"--docker-image", "my-image",
		"--env", "FOO=foo",
		// This should be set to the value from the local environment,
		// which we set to "bar" below
		"--env", "BAR",
		// This should be ignored because it's not set in the local
		// environment
		"--env", "NO_SUCH_VARIABLE",
		"--verbose",
	}

	args = append(defaultArgs, args...)
	metadata, archiveDir := TestRunBundle(t, dir, cifuzz, bundlePath, args...)
	defer fileutil.Cleanup(archiveDir)

	// Verify code revision given by `--branch` and `--commit-sha` flags
	assert.Equal(t, "my-branch", metadata.CodeRevision.Git.Branch)
	assert.Equal(t, "123456abcdef", metadata.CodeRevision.Git.Commit)

	// Verify that the metadata contains the Docker image
	assert.Equal(t, "my-image", metadata.RunEnvironment.Docker)

	// Verify the metadata contains the env vars
	require.Equal(t, []string{"FOO=foo", "BAR=bar"}, metadata.Fuzzers[0].EngineOptions.Env)

	// Verify that the metadata contains one fuzzer
	require.Equal(t, 1, len(metadata.Fuzzers))
	fuzzerMetadata := metadata.Fuzzers[0]

	// Verify that name is set
	assert.Equal(t, fuzzerMetadata.Name, "com.example.FuzzTestCase")

	// Verify that the dictionary has been packaged with the fuzzer
	dictPath = filepath.Join(archiveDir, fuzzerMetadata.Dictionary)
	require.FileExists(t, dictPath)
	content, err := os.ReadFile(dictPath)
	require.NoError(t, err)
	assert.Equal(t, "test-dictionary-content", string(content))

	// Verify that the seed corpus has been packaged with the fuzzer
	seedCorpusPath := filepath.Join(archiveDir, fuzzerMetadata.Seeds)
	require.DirExists(t, seedCorpusPath)

	// Verify that runtime dependencies have been packed
	jarPattern := filepath.Join(archiveDir, "runtime_deps", "*.jar")
	jarMatches, err := zglob.Glob(jarPattern)
	require.NoError(t, err)
	assert.Equal(t, 10, len(jarMatches))

	classPattern := filepath.Join(archiveDir, "runtime_deps", "**", "*.class")
	classMatches, err := zglob.Glob(classPattern)
	require.NoError(t, err)
	assert.Equal(t, 3, len(classMatches))

	// Verify that the manifest.jar has been created
	manifestJARPath := filepath.Join(archiveDir, "com.example.FuzzTestCase", "manifest.jar")
	require.FileExists(t, manifestJARPath)

	// Verify contents of manifest.jar
	extractedManifestPath := filepath.Join(archiveDir, "manifest")
	err = archiveutil.Unzip(manifestJARPath, extractedManifestPath)
	require.NoError(t, err)
	manifestFilePath := filepath.Join(extractedManifestPath, "META-INF", "MANIFEST.MF")
	require.FileExists(t, manifestFilePath)
	content, err = os.ReadFile(manifestFilePath)
	require.NoError(t, err)
	assert.Equal(t, "Jazzer-Fuzz-Target-Class: com.example.FuzzTestCase\n", string(content))
}

func TestBundleGradle(t *testing.T, dir string, cifuzz string, args ...string) {
	tempDir, err := os.MkdirTemp("", "cifuzz-archive-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)
	bundlePath := filepath.Join(tempDir, "fuzz_tests.tar.gz")
	t.Logf("creating test bundle in %s", tempDir)

	// Create a dictionary
	dictPath := filepath.Join(tempDir, "some_dict")
	err = os.WriteFile(dictPath, []byte("test-dictionary-content"), 0600)
	require.NoError(t, err)

	// Create a seed corpus directory with an empty seed
	seedCorpusDir, err := os.MkdirTemp(tempDir, "seeds-")
	require.NoError(t, err)
	err = fileutil.Touch(filepath.Join(seedCorpusDir, "empty"))
	require.NoError(t, err)

	defaultArgs := []string{
		"bundle",
		"-o", bundlePath,
		"--dict", dictPath,
		"--seed-corpus", seedCorpusDir,
		"--timeout", "100m",
		"--branch", "my-branch",
		"--commit", "123456abcdef",
		"--docker-image", "my-image",
		"--env", "FOO=foo",
		// This should be set to the value from the local environment,
		// which we set to "bar" below
		"--env", "BAR",
		// This should be ignored because it's not set in the local
		// environment
		"--env", "NO_SUCH_VARIABLE",
		"--verbose",
	}

	args = append(defaultArgs, args...)
	metadata, archiveDir := TestRunBundle(t, dir, cifuzz, bundlePath, args...)
	defer fileutil.Cleanup(archiveDir)

	// Verify code revision given by `--branch` and `--commit-sha` flags
	assert.Equal(t, "my-branch", metadata.CodeRevision.Git.Branch)
	assert.Equal(t, "123456abcdef", metadata.CodeRevision.Git.Commit)

	// Verify that the metadata contains the Docker image
	assert.Equal(t, "my-image", metadata.RunEnvironment.Docker)

	// Verify the metadata contains the env vars
	require.Equal(t, []string{"FOO=foo", "BAR=bar"}, metadata.Fuzzers[0].EngineOptions.Env)

	// Verify that the metadata contains one fuzzer
	require.Equal(t, 1, len(metadata.Fuzzers))
	fuzzerMetadata := metadata.Fuzzers[0]

	// Verify that name is set
	assert.Equal(t, fuzzerMetadata.Name, "com.example.FuzzTestCase")

	// Verify that the dictionary has been packaged with the fuzzer
	dictPath = filepath.Join(archiveDir, fuzzerMetadata.Dictionary)
	require.FileExists(t, dictPath)
	content, err := os.ReadFile(dictPath)
	require.NoError(t, err)
	assert.Equal(t, "test-dictionary-content", string(content))

	// Verify that the seed corpus has been packaged with the fuzzer
	seedCorpusPath := filepath.Join(archiveDir, fuzzerMetadata.Seeds)
	require.DirExists(t, seedCorpusPath)

	// Verify that runtime dependencies have been packed
	jarPattern := filepath.Join(archiveDir, "runtime_deps", "*.jar")
	jarMatches, err := zglob.Glob(jarPattern)
	require.NoError(t, err)
	assert.Equal(t, 17, len(jarMatches))

	classPattern := filepath.Join(archiveDir, "runtime_deps", "**", "*.class")
	classMatches, err := zglob.Glob(classPattern)
	require.NoError(t, err)
	assert.Equal(t, 3, len(classMatches))

	// Verify that the manifest.jar has been created
	manifestJARPath := filepath.Join(archiveDir, "com.example.FuzzTestCase", "manifest.jar")
	require.FileExists(t, manifestJARPath)

	// Verify contents of manifest.jar
	extractedManifestPath := filepath.Join(archiveDir, "manifest")
	err = archiveutil.Unzip(manifestJARPath, extractedManifestPath)
	require.NoError(t, err)
	manifestFilePath := filepath.Join(extractedManifestPath, "META-INF", "MANIFEST.MF")
	require.FileExists(t, manifestFilePath)
	content, err = os.ReadFile(manifestFilePath)
	require.NoError(t, err)
	assert.Equal(t, "Jazzer-Fuzz-Target-Class: com.example.FuzzTestCase\n", string(content))
}

func TestRunBundle(t *testing.T, dir string, cifuzz string, bundlePath string, args ...string) (*archive.Metadata, string) {
	// Bundle all fuzz tests into an archive.
	cmd := executil.Command(cifuzz, args...)
	cmd.Dir = dir
	env, err := envutil.Setenv(os.Environ(), "BAR", "bar")
	require.NoError(t, err)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	t.Logf("Command: %s", cmd.String())

	// Terminate the cifuzz process when we receive a termination signal
	// (else the test won't stop).
	TerminateOnSignal(t, cmd)

	err = cmd.Run()
	require.NoError(t, err)
	require.FileExists(t, bundlePath)

	// Extract the archive into a new temporary directory.
	archiveDir, err := os.MkdirTemp("", "cifuzz-extracted-archive-*")
	require.NoError(t, err)
	t.Cleanup(func() { fileutil.Cleanup(archiveDir) })
	err = archive.ExtractArchiveForTestsOnly(bundlePath, archiveDir)
	require.NoError(t, err)

	// List the files in the archive for easier debugging
	msg := fmt.Sprintf("Extracted archive at %s:\n", archiveDir)
	err = filepath.Walk(archiveDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				relPath, err := filepath.Rel(archiveDir, path)
				if err != nil {
					return err
				}
				msg += relPath + "\n"
			}
			return nil
		})
	t.Log(msg)
	require.NoError(t, err)

	// Read the bundle.yaml
	metadataPath := filepath.Join(archiveDir, "bundle.yaml")
	require.FileExists(t, metadataPath)
	metadataYaml, err := os.ReadFile(metadataPath)
	require.NoError(t, err)

	metadata := &archive.Metadata{}
	err = yaml.Unmarshal(metadataYaml, metadata)
	require.NoError(t, err)

	return metadata, archiveDir
}
