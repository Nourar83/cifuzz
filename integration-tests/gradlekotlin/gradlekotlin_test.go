package gradlekotlin

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/integration-tests/shared"
	builderPkg "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/internal/cmd/coverage/summary"
	"code-intelligence.com/cifuzz/pkg/parser/libfuzzer/stacktrace"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestIntegration_GradleKotlin_InitCreateRun(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	installDir := shared.InstallCIFuzzInTemp(t)
	t.Cleanup(func() { fileutil.Cleanup(installDir) })
	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))

	// Copy testdata
	projectDir := shared.CopyTestdataDir(t, "gradlekotlin")
	defer fileutil.Cleanup(projectDir)

	cifuzzRunner := shared.CIFuzzRunner{
		CIFuzzPath:      cifuzz,
		DefaultWorkDir:  projectDir,
		DefaultFuzzTest: "com.example.FuzzTestCase",
	}

	// Execute the init command
	linesToAdd := cifuzzRunner.Command(t, "init", nil)
	assert.FileExists(t, filepath.Join(projectDir, "cifuzz.yaml"))
	shared.AddLinesToFileAtBreakPoint(t, filepath.Join(projectDir, "build.gradle.kts"), linesToAdd, "dependencies {", true)

	// Execute the create command
	testDir := filepath.Join(
		"src",
		"test",
		"kotlin",
		"com",
		"example",
	)
	err := os.MkdirAll(filepath.Join(projectDir, testDir), 0755)
	require.NoError(t, err)
	outputPath := filepath.Join(testDir, "FuzzTestCase.kt")
	cifuzzRunner.Command(t, "create", &shared.CommandOptions{
		Args: []string{"kotlin", "--output", outputPath}},
	)

	// Check that the fuzz test was created in the correct directory
	fuzzTestPath := filepath.Join(projectDir, outputPath)
	require.FileExists(t, fuzzTestPath)

	// Check that the findings command doesn't list any findings yet
	findings := shared.GetFindings(t, cifuzz, projectDir)
	require.Empty(t, findings)

	// Run the (empty) fuzz test
	cifuzzRunner.Run(t, &shared.RunOptions{
		ExpectedOutputs:              []*regexp.Regexp{regexp.MustCompile(`^paths: \d+`)},
		TerminateAfterExpectedOutput: true,
	})

	// Make the fuzz test call a function
	modifyFuzzTestToCallFunction(t, fuzzTestPath)
	// Run the fuzz test
	expectedOutputExp := regexp.MustCompile(`High: Remote Code Execution`)
	cifuzzRunner.Run(t, &shared.RunOptions{
		ExpectedOutputs: []*regexp.Regexp{expectedOutputExp},
	})

	// Check that the findings command lists the finding
	findings = shared.GetFindings(t, cifuzz, projectDir)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0].Details, "Remote Code Execution")

	//// TODO: This check currently fails on macOS because there
	//// llvm-symbolizer doesn't read debug info from object files.
	//// See https://github.com/google/sanitizers/issues/207#issuecomment-136495556
	if runtime.GOOS != "darwin" {
		expectedStackTrace := []*stacktrace.StackFrame{
			{
				SourceFile:  "com.example.ExploreMe",
				Line:        19,
				Column:      0,
				FrameNumber: 0,
				Function:    "exploreMe",
			},
		}

		require.Equal(t, expectedStackTrace, findings[0].StackTrace)
	}

	// Check that options set via the config file are respected
	configFileContent := `use-sandbox: false`
	err = os.WriteFile(filepath.Join(projectDir, "cifuzz.yaml"), []byte(configFileContent), 0644)
	require.NoError(t, err)
	// When minijail is used, the artifact prefix is set to the minijail
	// output path
	cifuzzRunner.Run(t, &shared.RunOptions{
		ExpectedOutputs: []*regexp.Regexp{regexp.MustCompile(`artifact_prefix='./'`)},
	})

	if runtime.GOOS == "linux" {
		// Check that command-line flags take precedence over config file
		// settings (only on Linux because we only support Minijail on
		// Linux).
		cifuzzRunner.Run(t, &shared.RunOptions{
			Args:            []string{"--use-sandbox=true"},
			ExpectedOutputs: []*regexp.Regexp{regexp.MustCompile(`minijail`)},
		})
	}

	// Clear cifuzz.yml so that subsequent tests run with defaults (e.g. sandboxing).
	err = os.WriteFile(filepath.Join(projectDir, "cifuzz.yaml"), nil, 0644)
	require.NoError(t, err)

	// Produce a jacoco xml coverage report
	createJacocoXMLCoverageReport(t, cifuzz, projectDir)

	// Run cifuzz bundle and verify the contents of the archive.
	shared.TestBundleGradle(t, projectDir, cifuzz, "com.example.FuzzTestCase")
}

func createJacocoXMLCoverageReport(t *testing.T, cifuzz, dir string) {
	t.Helper()

	cmd := executil.Command(cifuzz, "coverage", "-v",
		"--output", "report", "com.example.FuzzTestCase")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err)

	// Check that the coverage report was created
	reportPath := filepath.Join(dir, "report", "jacoco.xml")
	require.FileExists(t, reportPath)

	// Check that the coverage report contains coverage for
	// ExploreMe.kt source file, but not for App.kt.
	reportFile, err := os.Open(reportPath)
	require.NoError(t, err)
	defer reportFile.Close()
	summary := summary.ParseJacocoXML(reportFile)

	for _, file := range summary.Files {
		if file.Filename == "com/example/ExploreMe.kt" {
			assert.Equal(t, 2, file.Coverage.FunctionsHit)
			assert.Equal(t, 10, file.Coverage.LinesHit)
			assert.Equal(t, 8, file.Coverage.BranchesHit)

		} else if file.Filename == "com/example/App.kt" {
			assert.Equal(t, 0, file.Coverage.FunctionsHit)
			assert.Equal(t, 0, file.Coverage.LinesHit)
			assert.Equal(t, 0, file.Coverage.BranchesHit)
		}
	}
}

func modifyFuzzTestToCallFunction(t *testing.T, fuzzTestPath string) {
	// Modify the fuzz test stub created by `cifuzz create` to actually
	// call a function.

	f, err := os.OpenFile(fuzzTestPath, os.O_RDWR, 0700)
	require.NoError(t, err)
	defer f.Close()
	scanner := bufio.NewScanner(f)

	var lines []string
	var seenBeginningOfFuzzTestFunc bool
	var addedFunctionCall bool
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "    @FuzzTest") {
			seenBeginningOfFuzzTestFunc = true
		}
		// Insert the function call at the end of the myFuzzTest
		// function, right above the "}".
		if seenBeginningOfFuzzTestFunc && strings.HasPrefix(scanner.Text(), "    }") {
			lines = append(lines, []string{
				"        int a = data.consumeInt();",
				"        int b = data.consumeInt();",
				"        String c = data.consumeRemainingAsString();",
				"		 ExploreMe ex = new ExploreMe(a);",
				"        ex.exploreMe(b, c);",
			}...)
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
}
