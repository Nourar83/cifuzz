package bundler

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/internal/bundler/archive"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/fileutil"
)

// A library in a system library directory that is not certain to exist in the Docker image.
const uncommonSystemDepUnix = "/usr/lib/libBLAS.so"

func TestAssembleArtifacts_Fuzzing(t *testing.T) {
	var err error

	// The project dir path has to be absolute
	projectDir, err := filepath.Abs(filepath.Join("testdata", "libfuzzer", "project"))
	require.NoError(t, err)

	externalDep, err := filepath.Abs(filepath.Join("testdata", "libfuzzer", "lib", "libexternal.so"))
	require.NoError(t, err)

	tempDir, err := os.MkdirTemp("", "bundle-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)

	fuzzTest := "some_fuzz_test"
	buildDir := filepath.Join(projectDir, "build")
	runtimeDeps := []string{
		// A library in the project's build directory.
		filepath.Join(buildDir, "lib", "helper.so"),
		externalDep,
	}
	if runtime.GOOS != "windows" {
		runtimeDeps = append(runtimeDeps, uncommonSystemDepUnix)
	}

	bundle, err := os.CreateTemp("", "bundle-archive-")
	require.NoError(t, err)
	bufWriter := bufio.NewWriter(bundle)
	archiveWriter := archive.NewArchiveWriter(bufWriter)

	b := newLibfuzzerBundler(&Opts{
		Env:     []string{"FOO=foo"},
		tempDir: tempDir,
	}, archiveWriter)

	// Assemble artifacts for fuzzer build results
	buildResult := &build.Result{
		Name:        fuzzTest,
		Executable:  filepath.Join(buildDir, fuzzTest),
		SeedCorpus:  filepath.Join(projectDir, "seeds"),
		BuildDir:    buildDir,
		Sanitizers:  []string{"address"},
		RuntimeDeps: runtimeDeps,
		ProjectDir:  projectDir,
	}
	fuzzers, systemDeps, err := b.assembleArtifacts(buildResult)
	require.NoError(t, err)

	require.Equal(t, 1, len(fuzzers))
	require.Equal(t, archive.Fuzzer{
		Target:        "some_fuzz_test",
		Path:          filepath.Join("libfuzzer", "address", "some_fuzz_test", "bin", "some_fuzz_test"),
		Engine:        "LIBFUZZER",
		Sanitizer:     "ADDRESS",
		ProjectDir:    projectDir,
		Seeds:         filepath.Join("libfuzzer", "address", "some_fuzz_test", "seeds"),
		LibraryPaths:  []string{filepath.Join("libfuzzer", "address", "some_fuzz_test", "external_libs")},
		EngineOptions: archive.EngineOptions{Env: []string{"FOO=foo", "NO_CIFUZZ=1"}},
	}, *fuzzers[0])

	if runtime.GOOS != "windows" {
		require.Equal(t, []string{uncommonSystemDepUnix}, systemDeps)
	}

	// Assemble artifacts for coverage build results
	buildResult = &build.Result{
		Name:        fuzzTest,
		Executable:  filepath.Join(buildDir, fuzzTest),
		SeedCorpus:  filepath.Join(projectDir, "seeds"),
		BuildDir:    buildDir,
		Sanitizers:  []string{"coverage"},
		RuntimeDeps: runtimeDeps,
		ProjectDir:  projectDir,
	}
	fuzzers, systemDeps, err = b.assembleArtifacts(buildResult)
	require.NoError(t, err)

	require.Equal(t, 1, len(fuzzers))
	assert.Equal(t, archive.Fuzzer{
		Target:       "some_fuzz_test",
		Path:         filepath.Join("replayer", "coverage", "some_fuzz_test", "bin", "some_fuzz_test"),
		Engine:       "LLVM_COV",
		ProjectDir:   projectDir,
		Seeds:        filepath.Join("replayer", "coverage", "some_fuzz_test", "seeds"),
		LibraryPaths: []string{filepath.Join("replayer", "coverage", "some_fuzz_test", "external_libs")},
		EngineOptions: archive.EngineOptions{
			Env:   []string{"FOO=foo", "NO_CIFUZZ=1"},
			Flags: []string{"-merge=1", "."},
		},
	}, *fuzzers[0])

	err = archiveWriter.Close()
	require.NoError(t, err)
	err = bufWriter.Flush()
	require.NoError(t, err)
	err = bundle.Close()
	require.NoError(t, err)

	// Unpack archive contents with tar.
	out, err := os.MkdirTemp("", "bundler-test-*")
	require.NoError(t, err)
	cmd := exec.Command("tar", "-xvf", bundle.Name(), "-C", out)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("Command: %v", cmd.String())
	err = cmd.Run()
	require.NoError(t, err)

	// Check that the archive has the expected contents
	expectedContents, err := listFilesRecursively(filepath.Join("testdata", "libfuzzer", "expected-archive-contents"))
	require.NoError(t, err)
	actualContents, err := listFilesRecursively(out)
	require.NoError(t, err)
	require.Equal(t, expectedContents, actualContents)
}
