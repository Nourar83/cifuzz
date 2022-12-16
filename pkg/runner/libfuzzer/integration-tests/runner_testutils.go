package integration_tests

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/report"
	"code-intelligence.com/cifuzz/pkg/runner/libfuzzer"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

// ChannelPassthrough pipes the reports from the runner package to a report channel
// and also prints them to stdout
type ChannelPassthrough struct {
	ch chan *report.Report
}

func (cp *ChannelPassthrough) Handle(report *report.Report) error {
	select {
	case cp.ch <- report:
		jsonString, err := stringutil.ToJsonString(report)
		if err != nil {
			return err
		}
		fmt.Println(jsonString)
	default:
	}
	return nil
}

// RunnerTest helps to execute tests for the runner package
type RunnerTest struct {
	FuzzTarget         string
	Engine             config.Engine
	GeneratedCorpusDir string
	Timeout            time.Duration
	EngineArgs         []string
	FuzzTestArgs       []string
	FuzzerEnv          []string
	DisableMinijail    bool
	RunsLimit          int
	LogOutput          *bytes.Buffer
	ProjectDir         string
}

func NewLibfuzzerTest(t *testing.T, buildDir, fuzzTarget string, disableMinijail bool) *RunnerTest {
	return &RunnerTest{
		FuzzTarget: FuzzTestExecutablePath(t, buildDir, fuzzTarget),
		Engine:     config.LIBFUZZER,
		// Use a deterministic random seed
		EngineArgs: []string{
			"-seed=1",
		},
		DisableMinijail: disableMinijail,
		// For those tests which don't set a custom runs limit, the
		// expected errors are found within 3000 runs.
		RunsLimit:  3000,
		LogOutput:  bytes.NewBuffer([]byte{}),
		ProjectDir: buildDir,
	}
}

// Start selects the needed runner and execute it with the given options
func (test *RunnerTest) Start(t *testing.T, reportCh chan *report.Report) error {
	var err error

	if test.GeneratedCorpusDir == "" {
		test.GeneratedCorpusDir, err = os.MkdirTemp("", "corpus")
		require.NoError(t, err)
		t.Cleanup(func() { fileutil.Cleanup(test.GeneratedCorpusDir) })
	}

	seedCorpusDir, err := os.MkdirTemp("", "seeds")
	require.NoError(t, err)
	t.Cleanup(func() { fileutil.Cleanup(seedCorpusDir) })

	if test.RunsLimit != -1 {
		// Limit the number of runs
		test.EngineArgs = append(test.EngineArgs, fmt.Sprintf("-runs=%d", test.RunsLimit))
	}

	libfuzzerOptions := &libfuzzer.RunnerOptions{
		EngineArgs:         test.EngineArgs,
		EnvVars:            test.FuzzerEnv,
		FuzzTarget:         test.FuzzTarget,
		FuzzTestArgs:       test.FuzzTestArgs,
		GeneratedCorpusDir: test.GeneratedCorpusDir,
		// To ease debugging, we write the output to stderr in addition
		// to the test.LogOutput buffer
		LogOutput:      io.MultiWriter(test.LogOutput, os.Stderr),
		ProjectDir:     test.ProjectDir,
		ReportHandler:  &ChannelPassthrough{ch: reportCh},
		SeedCorpusDirs: []string{seedCorpusDir},
		Timeout:        test.Timeout,
		UseMinijail:    !test.DisableMinijail,
		Verbose:        true,
	}
	defer close(reportCh)

	if test.Engine == config.LIBFUZZER {
		libfuzzerRunner := libfuzzer.NewRunner(libfuzzerOptions)
		return libfuzzerRunner.Run(context.Background())
	}

	return fmt.Errorf("unknown fuzzing engine for test execution")
}

// Run makes sure that all the test output gets captured
func (test *RunnerTest) Run(t *testing.T) (string, []*report.Report) {
	// create buffered channel for receiving the reports
	reportCh := make(chan *report.Report, 1024)

	err := test.Start(t, reportCh)
	require.NoError(t, err)

	// collecting reports
	reports := []*report.Report{}
	for report := range reportCh {
		reports = append(reports, report)
	}

	return test.LogOutput.String(), reports
}

func (test *RunnerTest) RequireSeedCorpusNotEmpty(t *testing.T) {
	seeds, err := os.ReadDir(test.GeneratedCorpusDir)
	require.NoError(t, err)
	require.NotEmpty(t, seeds, "corpus directory is empty: %s", test.GeneratedCorpusDir)
}
