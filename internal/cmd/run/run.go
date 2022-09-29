package run

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/internal/build/cmake"
	"code-intelligence.com/cifuzz/internal/build/other"
	"code-intelligence.com/cifuzz/internal/cmd/run/report_handler"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/completion"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runfiles"
	"code-intelligence.com/cifuzz/pkg/runner/libfuzzer"
	"code-intelligence.com/cifuzz/util/fileutil"
)

type runOptions struct {
	BuildSystem    string        `mapstructure:"build-system"`
	BuildCommand   string        `mapstructure:"build-command"`
	NumBuildJobs   uint          `mapstructure:"build-jobs"`
	Dictionary     string        `mapstructure:"dict"`
	EngineArgs     []string      `mapstructure:"engine-args"`
	FuzzTestArgs   []string      `mapstructure:"fuzz-test-args"`
	SeedCorpusDirs []string      `mapstructure:"seed-corpus-dirs"`
	Timeout        time.Duration `mapstructure:"timeout"`
	UseSandbox     bool          `mapstructure:"use-sandbox"`
	PrintJSON      bool          `mapstructure:"print-json"`

	ProjectDir string
	fuzzTest   string
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
}

func New() *cobra.Command {
	opts := &runOptions{}
	var bindFlags func()

	cmd := &cobra.Command{
		Use:   "run [flags] <fuzz test>",
		Short: "Build and run a fuzz test",
		Long: `This command builds and executes a fuzz test. The usage of this command
depends on the build system configured for the project:

 * For CMake, <fuzz test> is the name of the fuzz test as defined in the
   'add_fuzz_test' command in your CMakeLists.txt. Command completion for
   the <fuzz test> argument works if the fuzz test has been built before
   or after running 'cifuzz reload'. The '--build-command' flag is ignored.

 * For other build systems, a command which builds the fuzz test executable
   must be provided via the '--build-command' argument or the 'build-command'
   setting in cifuzz.yaml. In this case, <fuzz test> is the path to the fuzz
   test executable created by the build command. The value specified for
   <fuzz test> is available to the build command in the FUZZ_TEST environment
   variable. Example:

       echo "build-command: make clean && make \$FUZZ_TEST" >> cifuzz.yaml
       cifuzz run my_fuzz_test

   Alternatively, <fuzz test> can be the name of the fuzz test executable,
   which will then be searched for recursively in the current directory.`,
		ValidArgsFunction: completion.ValidFuzzTests,
		Args:              cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Bind viper keys to flags. We can't do this in the New
			// function, because that would re-bind viper keys which
			// were bound to the flags of other commands before.
			bindFlags()

			err := config.FindAndParseProjectConfig(opts)
			if err != nil {
				log.Errorf(err, "Failed to parse cifuzz.yaml: %v", err.Error())
				return cmdutils.WrapSilentError(err)
			}

			opts.fuzzTest = args[0]
			return opts.validate()
		},
		RunE: func(c *cobra.Command, args []string) error {
			cmd := runCmd{Command: c, opts: opts}
			return cmd.run()
		},
	}

	// Note: If a flag should be configurable via cifuzz.yaml as well,
	// bind it to viper in the PreRunE function.
	bindFlags = cmdutils.AddFlags(cmd,
		cmdutils.AddBuildCommandFlag,
		cmdutils.AddBuildJobsFlag,
		cmdutils.AddDictFlag,
		cmdutils.AddEngineArgFlag,
		cmdutils.AddFuzzTestArgFlag,
		cmdutils.AddPrintJSONFlag,
		cmdutils.AddProjectDirFlag,
		cmdutils.AddSeedCorpusFlag,
		cmdutils.AddTimeoutFlag,
		cmdutils.AddUseSandboxFlag,
	)

	return cmd
}

func (c *runCmd) run() error {
	depsOk, err := c.checkDependencies()
	if err != nil {
		return err
	}
	if !depsOk {
		return dependencies.Error()
	}

	buildResult, err := c.buildFuzzTest()
	if err != nil {
		return err
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

	err = c.printFinalMetrics(buildResult.SeedCorpus)
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

	if c.opts.BuildSystem == config.BuildSystemCMake {
		builder, err := cmake.NewBuilder(&cmake.BuilderOptions{
			ProjectDir: c.opts.ProjectDir,
			// TODO: Do not hardcode this value.
			Engine:     "libfuzzer",
			Sanitizers: sanitizers,
			Parallel: cmake.ParallelOptions{
				Enabled: viper.IsSet("build-jobs"),
				NumJobs: c.opts.NumBuildJobs,
			},
			Stdout: c.OutOrStdout(),
			Stderr: c.ErrOrStderr(),
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
		return buildResults[c.opts.fuzzTest], nil
	} else if c.opts.BuildSystem == config.BuildSystemOther {
		if runtime.GOOS == "windows" {
			return nil, errors.New("CMake is the only supported build system on Windows")
		}
		builder, err := other.NewBuilder(&other.BuilderOptions{
			BuildCommand: c.opts.BuildCommand,
			// TODO: Do not hardcode this value.
			Engine:     "libfuzzer",
			Sanitizers: sanitizers,
			Stdout:     c.OutOrStdout(),
			Stderr:     c.ErrOrStderr(),
		})
		if err != nil {
			return nil, err
		}
		buildResult, err := builder.Build(c.opts.fuzzTest)
		if err != nil {
			return nil, err
		}
		return buildResult, nil
	} else {
		return nil, errors.Errorf("Unsupported build system \"%s\"", c.opts.BuildSystem)
	}
}

func (c *runCmd) runFuzzTest(buildResult *build.Result) error {
	log.Infof("Running %s", pterm.Style{pterm.Reset, pterm.FgLightBlue}.Sprintf(c.opts.fuzzTest))
	log.Debugf("Executable: %s", buildResult.Executable)

	generatedCorpusDir := cmdutils.GeneratedCorpusDir(c.opts.ProjectDir, c.opts.fuzzTest)
	err := os.MkdirAll(generatedCorpusDir, 0755)
	if err != nil {
		return errors.WithStack(err)
	}
	log.Infof("Storing generated corpus in %s", fileutil.PrettifyPath(generatedCorpusDir))

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
	generatedCorpusDir, err = filepath.EvalSymlinks(generatedCorpusDir)
	if err != nil {
		return errors.WithStack(err)
	}
	for i, dir := range seedCorpusDirs {
		seedCorpusDirs[i], err = filepath.EvalSymlinks(dir)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	runnerOpts := &libfuzzer.RunnerOptions{
		FuzzTarget:         buildResult.Executable,
		GeneratedCorpusDir: generatedCorpusDir,
		SeedCorpusDirs:     seedCorpusDirs,
		ProjectDir:         c.opts.ProjectDir,
		ReadOnlyBindings:   []string{buildResult.BuildDir},
		Dictionary:         c.opts.Dictionary,
		EngineArgs:         c.opts.EngineArgs,
		FuzzTestArgs:       c.opts.FuzzTestArgs,
		ReportHandler:      c.reportHandler,
		Timeout:            c.opts.Timeout,
		UseMinijail:        c.opts.UseSandbox,
		Verbose:            viper.GetBool("verbose"),
		KeepColor:          !c.opts.PrintJSON,
		EnvVars:            []string{"NO_CIFUZZ=1"},
	}
	runner := libfuzzer.NewRunner(runnerOpts)

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

	err = routines.Wait()
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

func (c *runCmd) printFinalMetrics(seedCorpus string) error {
	numSeeds, err := countSeeds(append(c.opts.SeedCorpusDirs, c.generatedCorpusPath(), seedCorpus))
	if err != nil {
		return err
	}

	return c.reportHandler.PrintFinalMetrics(numSeeds)
}

func (c *runCmd) generatedCorpusPath() string {
	// Store the generated corpus in a single persistent directory per
	// fuzz test in a hidden subdirectory.
	return filepath.Join(c.opts.ProjectDir, ".cifuzz-corpus", c.opts.fuzzTest)
}

func (c *runCmd) checkDependencies() (bool, error) {
	deps := []dependencies.Key{dependencies.CLANG, dependencies.LLVM_SYMBOLIZER}
	if c.opts.BuildSystem == config.BuildSystemCMake {
		deps = append(deps, dependencies.CMAKE)
	}
	return dependencies.Check(deps, dependencies.Default, runfiles.Finder)
}

func countSeeds(seedCorpusDirs []string) (uint, error) {
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
