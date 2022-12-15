//go:build linux

package process_wrapper

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	builderPkg "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/pkg/runfiles"
)

func TestMain(m *testing.M) {
	installDir, err := os.MkdirTemp("", "process-wrapper-test-")
	if err != nil {
		log.Fatalf("Failed to create temp dir for tests: %+v", err)
	}
	opts := builderPkg.Options{
		Version:   "dev",
		TargetDir: installDir,
	}
	builder, err := builderPkg.NewCIFuzzBuilder(opts)
	if err != nil {
		builder.Cleanup()
		log.Fatalf("%+v", err)
	}
	err = builder.BuildProcessWrapper()
	if err != nil {
		builder.Cleanup()
		log.Fatalf("%+v", err)
	}
	runfiles.Finder = runfiles.RunfilesFinderImpl{InstallDir: builder.TargetDir}

	res := m.Run()
	builder.Cleanup()
	os.Exit(res)
}

func TestProcessWrapper_ChangesDirectory(t *testing.T) {
	processWrapperPath, err := runfiles.Finder.ProcessWrapperPath()
	require.NoError(t, err)
	tempDir, err := os.MkdirTemp("", "process_wrapper")
	require.NoError(t, err)

	var errbuf bytes.Buffer
	var outbuf bytes.Buffer
	cmd := exec.Command(processWrapperPath, tempDir, "--", "/usr/bin/pwd")
	cmd.Stderr = &errbuf
	cmd.Stdout = &outbuf
	err = cmd.Run()
	assert.NoError(t, err)
	assert.Empty(t, errbuf.String())
	assert.Equal(t, tempDir, strings.TrimSpace(outbuf.String()))
}
