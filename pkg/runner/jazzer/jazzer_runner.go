package jazzer

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/minijail"
	"code-intelligence.com/cifuzz/pkg/runfiles"
	fuzzer_runner "code-intelligence.com/cifuzz/pkg/runner"
	"code-intelligence.com/cifuzz/pkg/runner/libfuzzer"
	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

// List of non-open-sourced hooks that should be used for Java API fuzzing.
var customHooks = []string{
	"com.code_intelligence.jazzer.sanitizers.FileIOHooks",
	"com.code_intelligence.jazzer.sanitizers.SQLHooks",
}

type RunnerOptions struct {
	LibfuzzerOptions        *libfuzzer.RunnerOptions
	AutofuzzTarget          string
	TargetClass             string
	ClassPaths              []string
	InstrumentationExcludes []string
}

func (options *RunnerOptions) ValidateOptions() error {
	err := options.LibfuzzerOptions.ValidateOptions()
	if err != nil {
		return err
	}

	if options.AutofuzzTarget == "" && options.TargetClass == "" {
		return errors.New("Either a autofuzz target or a target class must be specified")
	}
	if options.AutofuzzTarget != "" && options.TargetClass != "" {
		return errors.New("Only specify either an autofuzz target or a target class")
	}

	return nil
}

type Runner struct {
	*RunnerOptions
	*libfuzzer.Runner
}

func NewRunner(options *RunnerOptions) *Runner {
	libfuzzerRunner := libfuzzer.NewRunner(options.LibfuzzerOptions)
	libfuzzerRunner.SupportJazzer = true
	return &Runner{options, libfuzzerRunner}
}

func (r *Runner) Run(ctx context.Context) error {
	err := r.ValidateOptions()
	if err != nil {
		return err
	}

	javaHome, err := runfiles.Finder.JavaHomePath()
	if err != nil {
		return err
	}

	javaBin := filepath.Join(javaHome, "bin", "java")
	if runtime.GOOS == "windows" {
		javaBin = filepath.Join(javaHome, "bin", "java.exe")
	}
	args := []string{javaBin}

	// class paths
	args = append(args, "-cp", strings.Join(r.ClassPaths, string(os.PathListSeparator)))

	// Jazzer main class
	args = append(args, "com.code_intelligence.jazzer.Jazzer")

	// ----------------------
	// --- Jazzer options ---
	// ----------------------
	if r.AutofuzzTarget != "" {
		args = append(args, "--autofuzz="+r.AutofuzzTarget)
	} else {
		args = append(args, "--target_class="+r.TargetClass)
	}

	if len(r.InstrumentationExcludes) > 0 {
		// Exclude specific classes from being instrumented for fuzzing
		excludes := strings.Join(r.InstrumentationExcludes, string(os.PathListSeparator))
		args = append(args, "--instrumentation_excludes="+excludes)
	}

	// -------------------------
	// --- libfuzzer options ---
	// -------------------------
	// Tell libfuzzer to exit after the timeout
	timeoutSeconds := strconv.FormatInt(int64(r.Timeout.Seconds()), 10)
	args = append(args, "-max_total_time="+timeoutSeconds)

	// Tell libfuzzer which dictionary it should use
	if r.Dictionary != "" {
		args = append(args, "-dict="+r.Dictionary)
	}

	// Add user-specified Jazzer/libfuzzer options
	args = append(args, r.EngineArgs...)

	// For Jazzer, we increase the default OOM limit further away from the JVM's maximum heap size of 1800 MB to
	// prevent spurious OOMs, which abort a fuzzing run.
	if !stringutil.ContainsStringWithPrefix(r.EngineArgs, "-rss_limit_mb=") {
		args = append(args, "-rss_limit_mb=3000")
	}

	// Tell libfuzzer which corpus directory it should use
	args = append(args, r.GeneratedCorpusDir)

	// Add any additional corpus directories as further positional arguments
	args = append(args, r.SeedCorpusDirs...)

	// -----------------------------
	// --- fuzz target arguments ---
	// -----------------------------
	if len(r.FuzzTestArgs) > 0 {
		// separate the Jazzer/libfuzzer arguments and fuzz test
		// arguments with a "--"
		args = append(args, "--")
		args = append(args, r.FuzzTestArgs...)
	}
	// -----------------------------

	// The environment we run the fuzzer in
	env, err := r.FuzzerEnvironment()
	if err != nil {
		return err
	}

	if r.UseMinijail {
		jazzerArgs := args

		bindings := []*minijail.Binding{
			// The first corpus directory must be writable, because
			// libfuzzer writes new test inputs to it
			{Source: r.GeneratedCorpusDir, Writable: minijail.ReadWrite},
		}

		for _, dir := range r.SeedCorpusDirs {
			bindings = append(bindings, &minijail.Binding{Source: dir})
		}

		// Add bindings for the Java dependencies
		for _, p := range r.ClassPaths {
			bindings = append(bindings, &minijail.Binding{Source: p})
		}

		// Add binding for the system JDK and pass it to minijail.
		bindings = append(bindings, &minijail.Binding{Source: javaHome})

		// Set up Minijail
		mj, err := minijail.NewMinijail(&minijail.Options{
			Args:     jazzerArgs,
			Bindings: bindings,
		})
		if err != nil {
			return err
		}
		defer mj.Cleanup()

		// Use the command which runs Jazzer via minijail
		args = mj.Args
	}

	return r.RunLibfuzzerAndReport(ctx, args, env)
}

func (r *Runner) FuzzerEnvironment() ([]string, error) {
	var env []string
	var err error

	env, err = fuzzer_runner.AddEnvFlags(env, r.EnvVars)
	if err != nil {
		return nil, err
	}

	// Try to find a reasonable JAVA_HOME if none is set.
	if _, set := envutil.LookupEnv(env, "JAVA_HOME"); !set {
		javaHome, err := runfiles.Finder.JavaHomePath()
		if err == nil {
		}
		env, err = envutil.Setenv(env, "JAVA_HOME", javaHome)
		if err != nil {
			return nil, err
		}
	}

	// Enable more verbose logging for Jazzer's libjvm.so search process.
	env, err = envutil.Setenv(env, "RULES_JNI_TRACE", "1")
	if err != nil {
		return nil, err
	}

	return env, nil
}

func (r *Runner) Cleanup(ctx context.Context) {
	r.Runner.Cleanup(ctx)
}
