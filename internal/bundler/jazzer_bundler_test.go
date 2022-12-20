package bundler

import (
	"bufio"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/pkg/artifact"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestAssembleArtifactsJava_Fuzzing(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bundle-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)
	require.NoError(t, err)

	projectDir := filepath.Join("testdata", "jazzer", "project")

	fuzzTest := "com.example.FuzzTest"
	anotherFuzzTest := "com.example.AnotherFuzzTest"
	buildDir := filepath.Join(projectDir, "target")

	runtimeDeps := []string{
		// A library in the project's build directory.
		filepath.Join(projectDir, "lib", "mylib.jar"),
		// a directory structure of class files
		filepath.Join(projectDir, "classes"),
		filepath.Join(projectDir, "test-classes"),
	}

	buildResults := []*build.Result{}
	buildResult := &build.Result{
		Name:        fuzzTest,
		BuildDir:    buildDir,
		RuntimeDeps: runtimeDeps,
		ProjectDir:  projectDir,
	}
	anotherBuildResult := &build.Result{
		Name:        anotherFuzzTest,
		BuildDir:    buildDir,
		RuntimeDeps: runtimeDeps,
		ProjectDir:  projectDir,
	}
	buildResults = append(buildResults, buildResult, anotherBuildResult)

	bundle, err := os.CreateTemp("", "bundle-archive-")
	require.NoError(t, err)
	bufWriter := bufio.NewWriter(bundle)
	archiveWriter := artifact.NewArchiveWriter(bufWriter)

	b := newJazzerBundler(&Opts{
		Env:     []string{"FOO=foo"},
		tempDir: tempDir,
	}, archiveWriter)
	fuzzers, err := b.assembleArtifacts(buildResults)
	require.NoError(t, err)

	err = archiveWriter.Close()
	require.NoError(t, err)
	err = bufWriter.Flush()
	require.NoError(t, err)
	err = bundle.Close()
	require.NoError(t, err)

	expectedDeps := []string{
		// manifest.jar should always be first element in runtime paths
		filepath.Join(fuzzTest, "manifest.jar"),
		filepath.Join("runtime_deps", "mylib.jar"),
		filepath.Join("runtime_deps", "classes"),
		filepath.Join("runtime_deps", "test-classes"),
	}
	expectedFuzzer := &artifact.Fuzzer{
		Name:         buildResult.Name,
		Engine:       "JAVA_LIBFUZZER",
		ProjectDir:   buildResult.ProjectDir,
		RuntimePaths: expectedDeps,
		EngineOptions: artifact.EngineOptions{
			Env:   b.opts.Env,
			Flags: b.opts.EngineArgs,
		},
	}
	require.Equal(t, 2, len(fuzzers))
	require.Equal(t, *expectedFuzzer, *fuzzers[0])

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
	expectedContents, err := listFilesRecursively(filepath.Join("testdata", "jazzer", "expected-archive-contents"))
	require.NoError(t, err)
	actualContents, err := listFilesRecursively(out)
	require.NoError(t, err)
	require.Equal(t, expectedContents, actualContents)
}

func listFilesRecursively(dir string) ([]string, error) {
	var paths []string

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return errors.WithStack(err)
		}
		paths = append(paths, relPath)
		return nil
	})
	return paths, err
}
