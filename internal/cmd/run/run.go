package run

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"code-intelligence.com/cifuzz/internal/access_tokens"
	"code-intelligence.com/cifuzz/internal/api"
	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/internal/build/bazel"
	"code-intelligence.com/cifuzz/internal/build/cmake"
	"code-intelligence.com/cifuzz/internal/build/gradle"
	"code-intelligence.com/cifuzz/internal/build/maven"
	"code-intelligence.com/cifuzz/internal/build/other"
	"code-intelligence.com/cifuzz/internal/cmd/run/report_handler"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/cmdutils/login"
	"code-intelligence.com/cifuzz/internal/cmdutils/resolve"
	"code-intelligence.com/cifuzz/internal/completion"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/dialog"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runner/jazzer"
	"code-intelligence.com/cifuzz/pkg/runner/libfuzzer"
	"code-intelligence.com/cifuzz/util/fileutil"
)

type runOptions struct {
	BuildSystem           string        `mapstructure:"build-system"`
	BuildCommand          string        `mapstructure:"build-command"`
	NumBuildJobs          uint          `mapstructure:"build-jobs"`
	Dictionary            string        `mapstructure:"dict"`
	EngineArgs            []string      `mapstructure:"engine-args"`
	SeedCorpusDirs        []string      `mapstructure:"seed-corpus-dirs"`
	Timeout               time.Duration `mapstructure:"timeout"`
	Interactive           bool          `mapstructure:"interactive"`
	Server                string        `mapstructure:"server"`
	UseSandbox            bool          `mapstructure:"use-sandbox"`
	PrintJSON             bool          `mapstructure:"print-json"`
	BuildOnly             bool          `mapstructure:"build-only"`
	ResolveSourceFilePath bool

	ProjectDir string
	fuzzTest   string
	argsToPass []string
}

func (opts *runOptions) validate() error {
	var err error

	opts.SeedCorpusDirs, err = cmdutils.ValidateSeedCorpusDirs(opts.SeedCorpusDirs)
	if err != nil {
		log.Error(err, err.Error())
		return cmdutils.ErrSilent
	}

	if opts.Dictionary != "" {
		// Check if the dictionary exists and can be accessed
		_, err := os.Stat(opts.Dictionary)
		if err != nil {
			err = errors.WithStack(err)
			log.Error(err, err.Error())
			return cmdutils.ErrSilent
		}
	}

	if opts.BuildSystem == "" {
		opts.BuildSystem, err = config.DetermineBuildSystem(opts.ProjectDir)
		if err != nil {
			return err
		}
	} else {
		err = config.ValidateBuildSystem(opts.BuildSystem)
		if err != nil {
			return err
		}
	}

	// To build with other build systems, a build command must be provided
	if opts.BuildSystem == config.BuildSystemOther && opts.BuildCommand == "" {
		msg := "Flag \"build-command\" must be set when using build system type \"other\""
		return cmdutils.WrapIncorrectUsageError(errors.New(msg))
	}

	if opts.Timeout != 0 && opts.Timeout < time.Second {
		msg := fmt.Sprintf("invalid argument %q for \"--timeout\" flag: timeout can't be less than a second", opts.Timeout)
		return cmdutils.WrapIncorrectUsageError(errors.New(msg))
	}

	return nil
}

type runCmd struct {
	*cobra.Command
	opts *runOptions

	reportHandler *report_handler.ReportHandler
	tempDir       string
}

type runner interface {
	Run(context.Context) error
	Cleanup(context.Context)
}

func New() *cobra.Command {
	opts := &runOptions{}
	var bindFlags func()

	cmd := &cobra.Command{
		Use:   "run [flags] <fuzz test> [--] [<build system arg>...] ",
		Short: "Build and run a fuzz test",
		Long: `This command builds and executes a fuzz test. The usage of this command
depends on the build system configured for the project.

` + pterm.Style{pterm.Reset, pterm.Bold}.Sprint("CMake") + `
  <fuzz test> is the name of the fuzz test defined in the add_fuzz_test
  command in your CMakeLists.txt.

  Command completion for the <fuzz test> argument is supported when the
  fuzz test was built before or after running 'cifuzz reload'.

  The --build-command flag is ignored.

  Additional CMake arguments can be passed after a "--". For example:

    cifuzz run my_fuzz_test -- -G Ninja

  The inputs found in the directory

    <fuzz test>_inputs

  are used as a starting point for the fuzzing run.

` + pterm.Style{pterm.Reset, pterm.Bold}.Sprint("Bazel") + `
  <fuzz test> is the name of the cc_fuzz_test target as defined in your
  BUILD file, either as a relative or absolute Bazel label.

  Command completion for the <fuzz test> argument is supported.

  The --build-command flag is ignored.

  Additional Bazel arguments can be passed after a "--". For example:

    cifuzz run my_fuzz_test -- --sandbox_debug

  The inputs found in the directory

    <fuzz test>_inputs

  are used as a starting point for the fuzzing run.

` + pterm.Style{pterm.Reset, pterm.Bold}.Sprint("Maven/Gradle") + `
  <fuzz test> is the name of the class containing the fuzz test.

  Command completion for the <fuzz test> argument is supported.

  The --build-command flag is ignored.

  The inputs found in the directory

    src/test/resources/.../<fuzz test>Inputs

  are used as a starting point for the fuzzing run.

` + pterm.Style{pterm.Reset, pterm.Bold}.Sprint("Other build systems") + `
  <fuzz test> is either the path or basename of the fuzz test executable
  created by the build command. If it's the basename, it will be searched
  for recursively in the current working directory.

  A command which builds the fuzz test executable must be provided via
  the --build-command flag or the build-command setting in cifuzz.yaml.

  The value specified for <fuzz test> is made available to the build
  command in the FUZZ_TEST environment variable. For example:

    echo "build-command: make clean && make \$FUZZ_TEST" >> cifuzz.yaml
    cifuzz run my_fuzz_test

  The inputs found in the directory
			
    <fuzz test>_inputs

  are used as a starting point for the fuzzing run.

`,
		ValidArgsFunction: completion.ValidFuzzTests,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Bind viper keys to flags. We can't do this in the New
			// function, because that would re-bind viper keys which
			// were bound to the flags of other commands before.
			bindFlags()

			// Check correct number of fuzz test args (exactly one)
			var lenFuzzTestArgs int
			var argsToPass []string
			if cmd.ArgsLenAtDash() != -1 {
				lenFuzzTestArgs = cmd.ArgsLenAtDash()
				argsToPass = args[cmd.ArgsLenAtDash():]
			} else {
				lenFuzzTestArgs = len(args)
			}
			if lenFuzzTestArgs != 1 {
				msg := fmt.Sprintf("Exactly one <fuzz test> argument must be provided, got %d", lenFuzzTestArgs)
				return cmdutils.WrapIncorrectUsageError(errors.New(msg))
			}

			err := config.FindAndParseProjectConfig(opts)
			if err != nil {
				log.Errorf(err, "Failed to parse cifuzz.yaml: %v", err.Error())
				return cmdutils.WrapSilentError(err)
			}

			fuzzTests, err := resolve.FuzzTestArgument(opts.ResolveSourceFilePath, args, opts.BuildSystem, opts.ProjectDir)
			if err != nil {
				log.Error(err)
				return cmdutils.WrapSilentError(err)
			}
			opts.fuzzTest = fuzzTests[0]

			opts.argsToPass = argsToPass
			return opts.validate()
		},
		RunE: func(c *cobra.Command, args []string) error {
			cmd := runCmd{Command: c, opts: opts}
			return cmd.run()
		},
	}

	// Note: If a flag should be configurable via cifuzz.yaml as well,
	// bind it to viper in the PreRunE function.
	funcs := []func(cmd *cobra.Command) func(){
		cmdutils.AddBuildCommandFlag,
		cmdutils.AddBuildJobsFlag,
		cmdutils.AddBuildOnlyFlag,
		cmdutils.AddDictFlag,
		cmdutils.AddEngineArgFlag,
		cmdutils.AddPrintJSONFlag,
		cmdutils.AddProjectDirFlag,
		cmdutils.AddSeedCorpusFlag,
		cmdutils.AddTimeoutFlag,
		cmdutils.AddUseSandboxFlag,
		cmdutils.AddResolveSourceFileFlag,
	}
	if os.Getenv("CIFUZZ_PRERELEASE") != "" {
		funcs = append(funcs, cmdutils.AddServerFlag, cmdutils.AddInteractiveFlag)
	}
	bindFlags = cmdutils.AddFlags(cmd, funcs...)
	return cmd
}

func (c *runCmd) run() error {
	err := c.checkDependencies()
	if err != nil {
		return err
	}

	if os.Getenv("CIFUZZ_PRERELEASE") != "" {
		err = c.setupSync()
		if err != nil {
			return err
		}
	}

	// Create a temporary directory which the builder can use to create
	// temporary files
	c.tempDir, err = os.MkdirTemp("", "cifuzz-run-")
	if err != nil {
		return errors.WithStack(err)
	}
	defer fileutil.Cleanup(c.tempDir)

	buildResult, err := c.buildFuzzTest()
	if err != nil {
		return err
	}

	if c.opts.BuildOnly {
		return nil
	}

	// Initialize the report handler. Only do this right before we start
	// the fuzz test, because this is storing a timestamp which is used
	// to figure out how long the fuzzing run is running.
	c.reportHandler, err = report_handler.NewReportHandler(&report_handler.ReportHandlerOptions{
		ProjectDir:    c.opts.ProjectDir,
		SeedCorpusDir: buildResult.SeedCorpus,
		PrintJSON:     c.opts.PrintJSON,
	})
	if err != nil {
		return err
	}

	err = c.runFuzzTest(buildResult)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && c.opts.UseSandbox {
			return cmdutils.WrapCouldBeSandboxError(err)
		}
		return err
	}

	c.reportHandler.PrintCrashingInputNote()

	err = c.printFinalMetrics(buildResult.GeneratedCorpus, buildResult.SeedCorpus)
	if err != nil {
		return err
	}

	return nil
}

func (c *runCmd) buildFuzzTest() (*build.Result, error) {
	// TODO: Do not hardcode these values.
	sanitizers := []string{"address"}
	// UBSan is not supported by MSVC
	// TODO: Not needed anymore when sanitizers are configurable,
	//       then we do want to fail if the user explicitly asked for
	//       UBSan.
	if runtime.GOOS != "windows" {
		sanitizers = append(sanitizers, "undefined")
	}

	if runtime.GOOS == "windows" &&
		(c.opts.BuildSystem != config.BuildSystemCMake &&
			c.opts.BuildSystem != config.BuildSystemMaven &&
			c.opts.BuildSystem != config.BuildSystemGradle) {

		return nil, errors.New("Build system unsupported on Windows")
	}

	switch c.opts.BuildSystem {
	case config.BuildSystemBazel:
		// The cc_fuzz_test rule defines multiple bazel targets: If the
		// name is "foo", it defines the targets "foo", "foo_bin", and
		// others. We need to run the "foo_bin" target but want to
		// allow users to specify either "foo" or "foo_bin", so we check
		// if the fuzz test name appended with "_bin" is a valid target
		// and use that in that case
		cmd := exec.Command("bazel", "query", c.opts.fuzzTest+"_bin")
		err := cmd.Run()
		if err == nil {
			c.opts.fuzzTest += "_bin"
		}

		builder, err := bazel.NewBuilder(&bazel.BuilderOptions{
			ProjectDir: c.opts.ProjectDir,
			Args:       c.opts.argsToPass,
			NumJobs:    c.opts.NumBuildJobs,
			Stdout:     c.OutOrStdout(),
			Stderr:     c.ErrOrStderr(),
			TempDir:    c.tempDir,
			Verbose:    viper.GetBool("verbose"),
		})
		if err != nil {
			return nil, err
		}
		buildResults, err := builder.BuildForRun([]string{c.opts.fuzzTest})
		if err != nil {
			return nil, err
		}
		return buildResults[0], nil
	case config.BuildSystemCMake:
		builder, err := cmake.NewBuilder(&cmake.BuilderOptions{
			ProjectDir: c.opts.ProjectDir,
			Args:       c.opts.argsToPass,
			Sanitizers: sanitizers,
			Parallel: cmake.ParallelOptions{
				Enabled: viper.IsSet("build-jobs"),
				NumJobs: c.opts.NumBuildJobs,
			},
			Stdout:    c.OutOrStdout(),
			Stderr:    c.ErrOrStderr(),
			BuildOnly: c.opts.BuildOnly,
		})
		if err != nil {
			return nil, err
		}
		err = builder.Configure()
		if err != nil {
			return nil, err
		}
		buildResults, err := builder.Build([]string{c.opts.fuzzTest})
		if err != nil {
			return nil, err
		}
		if c.opts.BuildOnly {
			return nil, nil
		}
		return buildResults[0], nil
	case config.BuildSystemMaven:
		if len(c.opts.argsToPass) > 0 {
			log.Warnf("Passing additional arguments is not supported for Maven.\n"+
				"These arguments are ignored: %s", strings.Join(c.opts.argsToPass, " "))
		}

		builder, err := maven.NewBuilder(&maven.BuilderOptions{
			ProjectDir: c.opts.ProjectDir,
			Parallel: maven.ParallelOptions{
				Enabled: viper.IsSet("build-jobs"),
				NumJobs: c.opts.NumBuildJobs,
			},
			Stdout: c.OutOrStdout(),
			Stderr: c.OutOrStderr(),
		})
		if err != nil {
			return nil, err
		}
		buildResult, err := builder.Build(c.opts.fuzzTest)
		if err != nil {
			return nil, err
		}
		return buildResult, err
	case config.BuildSystemGradle:
		if len(c.opts.argsToPass) > 0 {
			log.Warnf("Passing additional arguments is not supported for Gradle.\n"+
				"These arguments are ignored: %s", strings.Join(c.opts.argsToPass, " "))
		}

		builder, err := gradle.NewBuilder(&gradle.BuilderOptions{
			ProjectDir: c.opts.ProjectDir,
			Parallel: gradle.ParallelOptions{
				Enabled: viper.IsSet("build-jobs"),
				NumJobs: c.opts.NumBuildJobs,
			},
			Stdout: c.OutOrStdout(),
			Stderr: c.OutOrStderr(),
		})
		if err != nil {
			return nil, err
		}
		buildResult, err := builder.Build(c.opts.fuzzTest)
		if err != nil {
			return nil, err
		}
		return buildResult, err
	case config.BuildSystemOther:
		if len(c.opts.argsToPass) > 0 {
			log.Warnf("Passing additional arguments is not supported for build system type \"other\".\n"+
				"These arguments are ignored: %s", strings.Join(c.opts.argsToPass, " "))
		}

		builder, err := other.NewBuilder(&other.BuilderOptions{
			ProjectDir:   c.opts.ProjectDir,
			BuildCommand: c.opts.BuildCommand,
			Sanitizers:   sanitizers,
			Stdout:       c.OutOrStdout(),
			Stderr:       c.ErrOrStderr(),
		})
		if err != nil {
			return nil, err
		}
		buildResult, err := builder.Build(c.opts.fuzzTest)
		if err != nil {
			return nil, err
		}
		return buildResult, nil
	}

	return nil, errors.Errorf("Unsupported build system \"%s\"", c.opts.BuildSystem)
}

func (c *runCmd) runFuzzTest(buildResult *build.Result) error {
	log.Infof("Running %s", pterm.Style{pterm.Reset, pterm.FgLightBlue}.Sprintf(c.opts.fuzzTest))
	if buildResult.Executable != "" {
		log.Debugf("Executable: %s", buildResult.Executable)
	}

	err := os.MkdirAll(buildResult.GeneratedCorpus, 0o755)
	if err != nil {
		return errors.WithStack(err)
	}
	log.Infof("Storing generated corpus in %s", fileutil.PrettifyPath(buildResult.GeneratedCorpus))

	// Use user-specified seed corpus dirs (if any) and the default seed
	// corpus (if it exists)
	seedCorpusDirs := c.opts.SeedCorpusDirs
	exists, err := fileutil.Exists(buildResult.SeedCorpus)
	if err != nil {
		return err
	}
	if exists {
		seedCorpusDirs = append(seedCorpusDirs, buildResult.SeedCorpus)
	}

	// Ensure that symlinks are resolved to be able to add minijail
	// bindings for the corpus dirs.
	buildResult.GeneratedCorpus, err = filepath.EvalSymlinks(buildResult.GeneratedCorpus)
	if err != nil {
		return errors.WithStack(err)
	}
	for i, dir := range seedCorpusDirs {
		seedCorpusDirs[i], err = filepath.EvalSymlinks(dir)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	readOnlyBindings := []string{buildResult.BuildDir}
	if c.opts.BuildSystem == config.BuildSystemBazel {
		// The install base directory contains e.g. the script generated
		// by bazel via --script_path and must therefore be accessible
		// inside the sandbox.
		cmd := exec.Command("bazel", "info", "install_base")
		out, err := cmd.Output()
		if err != nil {
			// It's expected that bazel might fail due to user configuration,
			// so we print the error without the stack trace.
			err = cmdutils.WrapExecError(errors.WithStack(err), cmd)
			log.Error(err)
			return cmdutils.ErrSilent
		}
		installBase := strings.TrimSpace(string(out))
		readOnlyBindings = append(readOnlyBindings, installBase)
	}

	runnerOpts := &libfuzzer.RunnerOptions{
		Dictionary:         c.opts.Dictionary,
		EngineArgs:         c.opts.EngineArgs,
		EnvVars:            []string{"NO_CIFUZZ=1"},
		FuzzTarget:         buildResult.Executable,
		GeneratedCorpusDir: buildResult.GeneratedCorpus,
		KeepColor:          !c.opts.PrintJSON,
		ProjectDir:         c.opts.ProjectDir,
		ReadOnlyBindings:   []string{buildResult.BuildDir},
		ReportHandler:      c.reportHandler,
		SeedCorpusDirs:     seedCorpusDirs,
		Timeout:            c.opts.Timeout,
		UseMinijail:        c.opts.UseSandbox,
		Verbose:            viper.GetBool("verbose"),
	}

	var runner runner

	switch c.opts.BuildSystem {
	case config.BuildSystemCMake, config.BuildSystemBazel, config.BuildSystemOther:
		runner = libfuzzer.NewRunner(runnerOpts)
	case config.BuildSystemMaven, config.BuildSystemGradle:
		excludePatterns := []string{"org.apache.maven.**", "org.gradle.**"}
		runnerOpts := &jazzer.RunnerOptions{
			TargetClass:             c.opts.fuzzTest,
			ClassPaths:              buildResult.RuntimeDeps,
			InstrumentationExcludes: excludePatterns,
			LibfuzzerOptions:        runnerOpts,
		}
		runner = jazzer.NewRunner(runnerOpts)
	}

	return executeRunner(runner)
}

func (c *runCmd) printFinalMetrics(generatedCorpus, seedCorpus string) error {
	numCorpusEntries, err := countCorpusEntries(append(c.opts.SeedCorpusDirs, generatedCorpus, seedCorpus))
	if err != nil {
		return err
	}

	return c.reportHandler.PrintFinalMetrics(numCorpusEntries)
}

func (c *runCmd) checkDependencies() error {
	var deps []dependencies.Key
	switch c.opts.BuildSystem {
	case config.BuildSystemCMake:
		deps = []dependencies.Key{
			dependencies.CLANG,
			dependencies.LLVM_SYMBOLIZER,
			dependencies.CMAKE,
		}
	case config.BuildSystemMaven:
		deps = []dependencies.Key{
			dependencies.JAVA,
			dependencies.MAVEN,
		}
	case config.BuildSystemGradle:
		// First check if gradle wrapper exists and check for gradle in path otherwise
		wrapper, err := gradle.FindGradleWrapper(c.opts.ProjectDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		// TODO: Do we really not want to check that Java is installed
		// too when we found the gradle wrapper?
		if wrapper != "" {
			return nil
		}

		deps = []dependencies.Key{
			dependencies.JAVA,
			dependencies.GRADLE,
		}
	case config.BuildSystemOther:
		deps = []dependencies.Key{
			dependencies.CLANG,
			dependencies.LLVM_SYMBOLIZER,
		}
	case config.BuildSystemBazel:
		// All dependencies are managed via bazel but it should be checked
		// that the correct bazel version is installed
		deps = []dependencies.Key{
			dependencies.BAZEL,
		}
	default:
		return errors.Errorf("Unsupported build system \"%s\"", c.opts.BuildSystem)
	}

	depsErr := dependencies.Check(deps)
	if depsErr != nil {
		log.Error(depsErr)
		return cmdutils.WrapSilentError(depsErr)
	}
	return nil
}

func (c *runCmd) setupSync() error {
	interactive := viper.GetBool("interactive")

	if os.Getenv("CI") != "" {
		interactive = false
	}

	authenticated, err := getAuthStatus(c.opts.Server)
	if err != nil {
		return cmdutils.WrapSilentError(err)
	}

	if authenticated {
		log.Infof(`✓ You are authenticated.
Your results will be synced to the remote fuzzing server at %s`, c.opts.Server)
	} else if !interactive {
		log.Warn(`You are not authenticated with a remote fuzzing server.
Your results will not be synced to a remote fuzzing server.`)
	}

	if interactive && !authenticated {
		// establish server connection to check user auth
		err = showServerConnectionDialog(c.opts.Server)
		if err != nil {
			return cmdutils.WrapSilentError(err)
		}
	}
	return nil
}

func executeRunner(runner runner) error {
	// Handle cleanup (terminating the fuzzer process) when receiving
	// termination signals
	signalHandlerCtx, cancelSignalHandler := context.WithCancel(context.Background())
	routines, routinesCtx := errgroup.WithContext(signalHandlerCtx)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	var signalErr error
	routines.Go(func() error {
		select {
		case <-routinesCtx.Done():
			return nil
		case s := <-sigs:
			log.Warnf("Received %s", s.String())
			signalErr = cmdutils.NewSignalError(s.(syscall.Signal))
			runner.Cleanup(routinesCtx)
			return signalErr
		}
	})

	// Run the fuzzer
	routines.Go(func() error {
		defer cancelSignalHandler()
		return runner.Run(routinesCtx)
	})

	err := routines.Wait()
	// We use a separate variable to pass signal errors, because when
	// a signal was received, the first goroutine terminates the second
	// one, resulting in a race of which returns an error first. In that
	// case, we always want to print the signal error, not the
	// "Unexpected exit code" error from the runner.
	if signalErr != nil {
		log.Error(signalErr, signalErr.Error())
		return cmdutils.WrapSilentError(signalErr)
	}

	var execErr *cmdutils.ExecError
	if errors.As(err, &execErr) {
		// It's expected that libFuzzer might fail due to user
		// configuration, so we print the error without the stack trace.
		log.Error(err)
		return cmdutils.WrapSilentError(err)
	}

	return err
}

func countCorpusEntries(seedCorpusDirs []string) (uint, error) {
	var numSeeds uint
	for _, dir := range seedCorpusDirs {
		var seedsInDir uint
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			// Don't count empty files, same as libFuzzer
			if info.Size() != 0 {
				seedsInDir += 1
			}
			return nil
		})
		// Don't fail if the seed corpus dir doesn't exist
		if os.IsNotExist(err) {
			return 0, nil
		}
		if err != nil {
			return 0, errors.WithStack(err)
		}
		numSeeds += seedsInDir
	}
	return numSeeds, nil
}

func getAuthStatus(server string) (bool, error) {
	// Obtain the API access token
	token := login.GetToken(server)

	if token == "" {
		return false, nil
	}

	// Token might be invalid, so try to authenticate with it
	apiClient := api.APIClient{Server: server}
	err := login.CheckValidToken(&apiClient, token)
	if err != nil {
		err := errors.Errorf(`Failed to authenticate with the configured API access token.
It's possible that the token has been revoked. Please try again after
removing the token from %s.`, access_tokens.GetTokenFilePath())
		log.Warn(err.Error())

		return false, err
	}

	return true, nil
}

// showServerConnectionDialog ask users if they want to use a SaaS backend
// if they are not authenticated
func showServerConnectionDialog(server string) error {
	log.Notef(`Do you want to persist your findings?
Authenticate with the CI Fuzz Server (%s) to get more insights.`, server)

	wishOptions := map[string]string{
		"Yes":  "Yes",
		"Skip": "Skip",
	}
	wishToAuthenticate, err := dialog.Select("Do you want to authenticate?", wishOptions, false)
	if err != nil {
		return err
	}

	if wishToAuthenticate == "Yes" {
		apiClient := api.APIClient{Server: server}
		_, err := login.ReadCheckAndStoreTokenInteractively(&apiClient)
		if err != nil {
			return err
		}
	}

	return nil
}
