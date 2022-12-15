package llvm

import (
	"bytes"
	"debug/macho"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/pkg/errors"
	"github.com/pterm/pterm"
	"github.com/spf13/viper"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/internal/build/cmake"
	"code-intelligence.com/cifuzz/internal/build/other"
	"code-intelligence.com/cifuzz/internal/cmd/coverage/summary"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/binary"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/minijail"
	"code-intelligence.com/cifuzz/pkg/runfiles"
	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

type LLVMCoverageGenerator struct {
	OutputFormat   string
	OutputPath     string
	BuildSystem    string
	BuildCommand   string
	NumBuildJobs   uint
	SeedCorpusDirs []string
	UseSandbox     bool
	FuzzTest       string
	ProjectDir     string

	StdOut io.Writer
	StdErr io.Writer

	buildResult    *build.Result
	tmpDir         string
	outputDir      string
	runfilesFinder runfiles.RunfilesFinder
}

func (cov *LLVMCoverageGenerator) Generate() (string, error) {

	// ensure a finder is set
	if cov.runfilesFinder == nil {
		cov.runfilesFinder = runfiles.Finder
	}

	var err error
	cov.tmpDir, err = os.MkdirTemp("", "llvm-coverage-")
	if err != nil {
		return "", errors.WithStack(err)
	}
	cov.outputDir = filepath.Join(cov.tmpDir, "output")
	err = os.Mkdir(cov.outputDir, 0o755)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer fileutil.Cleanup(cov.tmpDir)

	err = cov.build()
	if err != nil {
		return "", err
	}

	err = cov.run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && cov.UseSandbox {
			return "", cmdutils.WrapCouldBeSandboxError(err)
		}
		return "", err
	}

	reportPath, err := cov.report()
	if err != nil {
		return "", err
	}
	return reportPath, nil
}

func (cov *LLVMCoverageGenerator) build() error {
	switch cov.BuildSystem {
	case config.BuildSystemCMake:
		builder, err := cmake.NewBuilder(&cmake.BuilderOptions{
			ProjectDir: cov.ProjectDir,
			Engine:     "libfuzzer",
			Sanitizers: []string{"coverage"},
			Parallel: cmake.ParallelOptions{
				Enabled: viper.IsSet("build-jobs"),
				NumJobs: uint(cov.NumBuildJobs),
			},
			Stdout: cov.StdOut,
			Stderr: cov.StdErr,
			// We want the runtime deps in the build result because we
			// pass them to the llvm-cov command.
			FindRuntimeDeps: true,
		})
		if err != nil {
			return err
		}
		err = builder.Configure()
		if err != nil {
			return err
		}
		buildResults, err := builder.Build([]string{cov.FuzzTest})
		if err != nil {
			return err
		}
		cov.buildResult = buildResults[0]
		return nil

	case config.BuildSystemOther:
		if runtime.GOOS == "windows" {
			return errors.New("CMake is the only supported build system on Windows")
		}
		builder, err := other.NewBuilder(&other.BuilderOptions{
			ProjectDir:     cov.ProjectDir,
			BuildCommand:   cov.BuildCommand,
			Engine:         "libfuzzer",
			Sanitizers:     []string{"coverage"},
			RunfilesFinder: cov.runfilesFinder,
			Stdout:         cov.StdOut,
			Stderr:         cov.StdErr,
		})
		if err != nil {
			return err
		}
		buildResult, err := builder.Build(cov.FuzzTest)
		if err != nil {
			return err
		}
		cov.buildResult = buildResult
		return nil

	}
	return errors.New("unknown build system")
}

func (cov *LLVMCoverageGenerator) run() error {
	log.Infof("Running %s on corpus", pterm.Style{pterm.Reset, pterm.FgLightBlue}.Sprint(cov.FuzzTest))
	log.Debugf("Executable: %s", cov.buildResult.Executable)

	// Use user-specified seed corpus dirs (if any), the default seed
	// corpus (if it exists), and the generated corpus (if it exists).
	corpusDirs := cov.SeedCorpusDirs
	exists, err := fileutil.Exists(cov.buildResult.SeedCorpus)
	if err != nil {
		return err
	}
	if exists {
		corpusDirs = append(corpusDirs, cov.buildResult.SeedCorpus)
	}
	exists, err = fileutil.Exists(cov.buildResult.GeneratedCorpus)
	if err != nil {
		return err
	}
	if exists {
		corpusDirs = append(corpusDirs, cov.buildResult.GeneratedCorpus)
	}

	// Ensure that symlinks are resolved to be able to add minijail
	// bindings for the corpus dirs.
	for i, dir := range corpusDirs {
		corpusDirs[i], err = filepath.EvalSymlinks(dir)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	executable := cov.buildResult.Executable
	conModeSupport := binary.SupportsLlvmProfileContinuousMode(executable)
	env := os.Environ()
	env, err = envutil.Setenv(env, "LLVM_PROFILE_FILE", cov.rawProfilePattern(conModeSupport))
	if err != nil {
		return err
	}
	env, err = envutil.Setenv(env, "NO_CIFUZZ", "1")
	if err != nil {
		return err
	}

	dirWithEmptyFile := filepath.Join(cov.outputDir, "empty-file-corpus")
	err = os.Mkdir(dirWithEmptyFile, 0o755)
	if err != nil {
		return err
	}
	err = fileutil.Touch(filepath.Join(dirWithEmptyFile, "empty_file"))
	if err != nil {
		return err
	}

	emptyDir := filepath.Join(cov.outputDir, "merge-target")
	err = os.Mkdir(emptyDir, 0o755)
	if err != nil {
		return err
	}
	artifactsDir := filepath.Join(cov.outputDir, "merge-artifacts")
	err = os.Mkdir(artifactsDir, 0o755)
	if err != nil {
		return err
	}

	// libFuzzer emits crashing inputs in merge mode, but these aren't useful as we only run on already known inputs.
	// Since there is no way to disable this behavior in libFuzzer, we instead emit artifacts into a dedicated temporary
	// directory that is thrown away after the coverage run.
	args := []string{"-artifact_prefix=" + artifactsDir + "/"}

	// libFuzzer's merge mode never runs the empty input, whereas regular fuzzing runs and the replayer always try the
	// empty input first. To achieve consistent behavior, manually run the empty input, ignoring any crashes. runFuzzer
	// always logs any error we encounter.
	// This line is responsible for empty inputs being skipped:
	// https://github.com/llvm/llvm-project/blob/c7c0ce7d9ebdc0a49313bc77e14d1e856794f2e0/compiler-rt/lib/fuzzer/FuzzerIO.cpp#L127
	_ = cov.runFuzzer(append(args, "-runs=0"), []string{dirWithEmptyFile}, env)

	// We use libFuzzer's crash-resistant merge mode to merge all corpus directories into an empty directory, which
	// makes libFuzzer go over all inputs in a subprocess that is restarted in case it crashes. With LLVM's continuous
	// mode (see rawProfilePattern) and since the LLVM coverage information is automatically appended to the existing
	// .profraw file, we collect complete coverage information even if the target crashes on an input in the corpus.
	return cov.runFuzzer(append(args, "-merge=1"), append([]string{emptyDir}, corpusDirs...), env)
}

func (cov *LLVMCoverageGenerator) runFuzzer(preCorpusArgs []string, corpusDirs []string, env []string) error {
	args := []string{cov.buildResult.Executable}
	args = append(args, preCorpusArgs...)
	args = append(args, corpusDirs...)

	if cov.UseSandbox {
		bindings := []*minijail.Binding{
			// The fuzz target must be accessible
			{Source: cov.buildResult.Executable},
		}

		for _, dir := range corpusDirs {
			bindings = append(bindings, &minijail.Binding{Source: dir})
		}

		// Set up Minijail
		mj, err := minijail.NewMinijail(&minijail.Options{
			Args:      args,
			Bindings:  bindings,
			OutputDir: cov.outputDir,
		})
		if err != nil {
			return err
		}
		defer mj.Cleanup()

		// Use the command which runs the fuzz test via minijail
		args = mj.Args
	}

	cmd := executil.Command(args[0], args[1:]...)
	cmd.Env = env

	errStream := &bytes.Buffer{}
	if viper.GetBool("verbose") {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else if cov.UseSandbox {
		cmd.Stderr = minijail.NewOutputFilter(errStream)
	} else {
		cmd.Stderr = errStream
	}

	log.Debugf("Command: %s", strings.Join(stringutil.QuotedStrings(cmd.Args), " "))
	err := cmd.Run()
	if err != nil {
		// Print the stderr output of the fuzzer to provide users with
		// the context of this error even without verbose mode.
		if !viper.GetBool("verbose") {
			log.Print(errStream.String())
		}
		// It's expected that the fuzz test executable might fail, so we
		// print the error without the stack trace.
		err = cmdutils.WrapExecError(errors.WithStack(err), cmd.Cmd)
		log.Error(err)
		return cmdutils.ErrSilent
	}
	return err
}

func (cov *LLVMCoverageGenerator) report() (string, error) {
	err := cov.indexRawProfile()
	if err != nil {
		return "", err
	}

	lcovReportSummary, err := cov.lcovReportSummary()
	if err != nil {
		return "", err
	}
	reportReader := strings.NewReader(lcovReportSummary)
	summary.ParseLcov(reportReader).PrintTable(cov.StdErr)

	reportPath := ""
	switch cov.OutputFormat {
	case "html":
		reportPath, err = cov.generateHTMLReport()
		if err != nil {
			return "", err
		}

	case "lcov":
		reportPath, err = cov.generateLcovReport()
		if err != nil {
			return "", err
		}
	}

	return reportPath, nil
}

func (cov *LLVMCoverageGenerator) indexRawProfile() error {
	rawProfileFiles, err := cov.rawProfileFiles()
	if err != nil {
		return err
	}
	if len(rawProfileFiles) == 0 {
		// The rawProfilePattern parameter only governs whether we add "%c",
		// which doesn't affect the actual raw profile location.
		return errors.Errorf("%s did not generate .profraw files at %s", cov.buildResult.Executable, cov.rawProfilePattern(false))
	}

	llvmProfData, err := cov.runfilesFinder.LLVMProfDataPath()
	if err != nil {
		return err
	}

	args := append([]string{"merge", "-sparse", "-o", cov.indexedProfilePath()}, rawProfileFiles...)
	cmd := exec.Command(llvmProfData, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Debugf("Command: %s", strings.Join(stringutil.QuotedStrings(cmd.Args), " "))
	err = cmd.Run()
	if err != nil {
		return cmdutils.WrapExecError(errors.WithStack(err), cmd)
	}
	return nil
}

func (cov *LLVMCoverageGenerator) rawProfilePattern(supportsContinuousMode bool) string {
	// Use "%m" instead of a fixed path to support coverage of shared
	// libraries: Each executable or library generates its own profile
	// file, all of which we have to merge in the end. By using "%m",
	// the profile is written to a unique file for each executable and
	// shared library.
	// Use "%c", if supported, which expands out to nothing, to enable the
	// continuous mode in which the .profraw is mmaped and thus kept in sync with
	// the counters in the instrumented code even when it crashes.
	// https://clang.llvm.org/docs/SourceBasedCodeCoverage.html#running-the-instrumented-program
	basePattern := "%m.profraw"
	if supportsContinuousMode {
		basePattern = "%c" + basePattern
	}
	return filepath.Join(cov.outputDir, basePattern)
}

func (cov *LLVMCoverageGenerator) generateHTMLReport() (string, error) {
	args := []string{"export", "-format=lcov"}
	ignoreCIFuzzIncludesArgs, err := cov.getIgnoreCIFuzzIncludesArgs()
	if err != nil {
		return "", err
	}
	args = append(args, ignoreCIFuzzIncludesArgs...)
	report, err := cov.runLlvmCov(args)
	if err != nil {
		return "", err
	}
	// Write lcov report to temp dir
	reportDir, err := os.MkdirTemp("", "coverage-")
	if err != nil {
		return "", errors.WithStack(err)
	}
	lcovReport := filepath.Join(reportDir, "coverage.lcov")
	err = os.WriteFile(lcovReport, []byte(report), 0o644)
	if err != nil {
		return "", errors.WithStack(err)
	}

	if cov.OutputPath == "" {
		// If no output path is specified, we create the output in a
		// temporary directory.
		outputDir, err := os.MkdirTemp("", "coverage-")
		if err != nil {
			return "", errors.WithStack(err)
		}
		cov.OutputPath = filepath.Join(outputDir, cov.executableName())
	}

	// Create an HTML report via genhtml
	genHTML, err := runfiles.Finder.GenHTMLPath()
	if err != nil {
		return "", err
	}
	args = []string{"--prefix", cov.ProjectDir, "--output", cov.OutputPath, lcovReport}

	cmd := exec.Command(genHTML, args...)
	cmd.Dir = cov.ProjectDir
	cmd.Stderr = os.Stderr
	log.Debugf("Command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		return "", errors.WithStack(err)
	}

	return cov.OutputPath, nil
}

func (cov *LLVMCoverageGenerator) runLlvmCov(args []string) (string, error) {
	llvmCov, err := cov.runfilesFinder.LLVMCovPath()
	if err != nil {
		return "", err
	}

	// Add all runtime dependencies of the fuzz test to the binaries
	// processed by llvm-cov to include them in the coverage report
	args = append(args, "-instr-profile="+cov.indexedProfilePath())
	args = append(args, cov.buildResult.Executable)
	if archArg, err := cov.archFlagIfNeeded(cov.buildResult.Executable); err != nil {
		return "", err
	} else if archArg != "" {
		args = append(args, archArg)
	}
	for _, path := range cov.buildResult.RuntimeDeps {
		args = append(args, "-object="+path)
		if archArg, err := cov.archFlagIfNeeded(path); err != nil {
			return "", err
		} else if archArg != "" {
			args = append(args, archArg)
		}
	}

	cmd := exec.Command(llvmCov, args...)
	cmd.Stderr = os.Stderr
	log.Debugf("Command: %s", strings.Join(stringutil.QuotedStrings(cmd.Args), " "))
	output, err := cmd.Output()
	if err != nil {
		return "", cmdutils.WrapExecError(errors.WithStack(err), cmd)
	}
	return string(output), nil
}

func (cov *LLVMCoverageGenerator) generateLcovReport() (string, error) {
	args := []string{"export", "-format=lcov"}
	ignoreCIFuzzIncludesArgs, err := cov.getIgnoreCIFuzzIncludesArgs()
	if err != nil {
		return "", err
	}
	args = append(args, ignoreCIFuzzIncludesArgs...)
	report, err := cov.runLlvmCov(args)
	if err != nil {
		return "", err
	}

	outputPath := cov.OutputPath
	if cov.OutputPath == "" {
		// If no output path is specified, we create the output in the
		// current working directory. We don't create it in a temporary
		// directory like we do for HTML reports, because we can't open
		// the lcov report in a browser, so the command is only useful
		// if the lcov report is accessible after it was created.
		outputPath = cov.executableName() + ".coverage.lcov"
	}

	err = os.WriteFile(outputPath, []byte(report), 0o644)
	if err != nil {
		return "", errors.WithStack(err)
	}

	log.Debugf("Created lcov trace file: %s", outputPath)
	return outputPath, nil
}

func (cov *LLVMCoverageGenerator) lcovReportSummary() (string, error) {
	args := []string{"export", "-format=lcov", "-summary-only"}
	ignoreCIFuzzIncludesArgs, err := cov.getIgnoreCIFuzzIncludesArgs()
	if err != nil {
		return "", err
	}
	args = append(args, ignoreCIFuzzIncludesArgs...)
	output, err := cov.runLlvmCov(args)
	if err != nil {
		return "", err
	}

	return output, nil
}

func (cov *LLVMCoverageGenerator) getIgnoreCIFuzzIncludesArgs() ([]string, error) {
	cifuzzIncludePath, err := cov.runfilesFinder.CIFuzzIncludePath()
	if err != nil {
		return nil, err
	}
	return []string{"-ignore-filename-regex=" + regexp.QuoteMeta(cifuzzIncludePath) + "/.*"}, nil
}

func (cov *LLVMCoverageGenerator) rawProfileFiles() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(cov.outputDir, "*.profraw"))
	return files, errors.WithStack(err)
}

func (cov *LLVMCoverageGenerator) indexedProfilePath() string {
	return filepath.Join(cov.tmpDir, filepath.Base(cov.buildResult.Executable)+".profdata")
}

func (cov *LLVMCoverageGenerator) executableName() string {
	return filepath.Base(cov.buildResult.Executable)
}

// Returns an llvm-cov -arch flag indicating the preferred architecture of the given object on macOS, where objects can
// be "universal", that is, contain versions for multiple architectures.
func (cov *LLVMCoverageGenerator) archFlagIfNeeded(object string) (string, error) {
	if runtime.GOOS != "darwin" {
		// Only macOS uses universal binaries that bundle multiple architectures.
		return "", nil
	}
	var cifuzzCPU macho.Cpu
	if runtime.GOARCH == "amd64" {
		cifuzzCPU = macho.CpuAmd64
	} else {
		cifuzzCPU = macho.CpuArm64
	}
	fatFile, fatErr := macho.OpenFat(object)
	if fatErr == nil {
		defer fatFile.Close()
		var fallbackCPU macho.Cpu
		for _, arch := range fatFile.Arches {
			// Give preference to the architecture matching that of the cifuzz binary.
			if arch.Cpu == cifuzzCPU {
				return cov.cpuToArchFlag(arch.Cpu)
			}
			if arch.Cpu == macho.CpuAmd64 || arch.Cpu == macho.CpuArm64 {
				fallbackCPU = arch.Cpu
			}
		}
		return cov.cpuToArchFlag(fallbackCPU)
	}
	file, err := macho.Open(object)
	if err == nil {
		defer file.Close()
		return cov.cpuToArchFlag(file.Cpu)
	}
	return "", errors.Errorf("failed to parse Mach-O file %q: %q (as universal binary), %q", object, fatErr, err)
}

func (cov *LLVMCoverageGenerator) cpuToArchFlag(cpu macho.Cpu) (string, error) {
	switch cpu {
	case macho.CpuArm64:
		return "-arch=arm64", nil
	case macho.CpuAmd64:
		return "-arch=x86_64", nil
	default:
		return "", errors.Errorf("unsupported architecture: %s", cpu.String())
	}
}
