package cmdutils

import (
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func MarkFlagsRequired(cmd *cobra.Command, flags ...string) {
	for _, flag := range flags {
		err := cmd.MarkFlagRequired(flag)
		if err != nil {
			panic(err)
		}
	}
}

func ViperMustBindPFlag(key string, flag *pflag.Flag) {
	err := viper.BindPFlag(key, flag)
	if err != nil {
		panic(err)
	}
}

// AddFlags executes the specified Add*Flag functions and returns a
// function which binds all those flags to viper
func AddFlags(cmd *cobra.Command, funcs ...func(cmd *cobra.Command) func()) (bindFlags func()) { // nolint:nonamedreturns
	var bindFlagFuncs []func()
	for _, f := range funcs {
		bindFlagFunc := f(cmd)
		bindFlagFuncs = append(bindFlagFuncs, bindFlagFunc)
	}
	return func() {
		for _, f := range bindFlagFuncs {
			f()
		}
	}
}

func AddBranchFlag(cmd *cobra.Command) func() {
	cmd.Flags().String("branch", "",
		"Branch name to use in the bundle config.\n"+
			"By default, the currently checked out git branch is used.")
	return func() {
		ViperMustBindPFlag("branch", cmd.Flags().Lookup("branch"))
	}
}

func AddBuildCommandFlag(cmd *cobra.Command) func() {
	cmd.Flags().String("build-command", "",
		"The `command` to build the fuzz test for other build systems.")
	return func() {
		ViperMustBindPFlag("build-command", cmd.Flags().Lookup("build-command"))
	}
}

func AddBuildJobsFlag(cmd *cobra.Command) func() {
	cmd.Flags().Uint("build-jobs", 0,
		"Maximum number of concurrent processes to use when building.\n"+
			"If argument is omitted the native build tool's default number is used.")
	cmd.Flags().Lookup("build-jobs").NoOptDefVal = "0"
	return func() {
		ViperMustBindPFlag("build-jobs", cmd.Flags().Lookup("build-jobs"))
	}
}

func AddCommitFlag(cmd *cobra.Command) func() {
	cmd.Flags().String("commit", "",
		"Commit to use in the bundle config.\n"+
			"By default, the head of the currently checked out git branch is used.")
	return func() {
		ViperMustBindPFlag("commit", cmd.Flags().Lookup("commit"))
	}
}

func AddDictFlag(cmd *cobra.Command) func() {
	// TODO(afl): Also link to https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/README.md
	cmd.Flags().String("dict", "",
		"A `file` containing input language keywords or other interesting byte sequences.\n"+
			"See https://llvm.org/docs/LibFuzzer.html#dictionaries.")
	return func() {
		ViperMustBindPFlag("dict", cmd.Flags().Lookup("dict"))
	}
}

func AddDockerImageFlag(cmd *cobra.Command) func() {
	cmd.Flags().String("docker-image", "ubuntu:rolling",
		"Docker image to use in the bundle config. This image will be used when\n"+
			"the bundle is executed on a remote fuzzing server.")
	return func() {
		ViperMustBindPFlag("docker-image", cmd.Flags().Lookup("docker-image"))
	}
}

func AddEngineArgFlag(cmd *cobra.Command) func() {
	// TODO(afl): Also link to https://www.mankier.com/8/afl-fuzz
	cmd.Flags().StringArray("engine-arg", nil,
		"Command-line `argument` to pass to the fuzzing engine.\n"+
			"See https://llvm.org/docs/LibFuzzer.html#options.\n"+
			"This flag can be used multiple times.")
	return func() {
		ViperMustBindPFlag("engine-args", cmd.Flags().Lookup("engine-arg"))
	}
}

func AddEnvFlag(cmd *cobra.Command) func() {
	cmd.Flags().StringArray("env", nil,
		"Set environment variable when executing fuzz tests, e.g. '--env `VAR=value`'.\n"+
			"To use the value of VAR in the local environment, use '--env VAR'.\n"+
			"This flag can be used multiple times.")
	return func() {
		ViperMustBindPFlag("env", cmd.Flags().Lookup("env"))
	}
}

func AddInteractiveFlag(cmd *cobra.Command) func() {
	cmd.Flags().Bool("interactive", true, "Toggle interactive prompting in the terminal")
	return func() {
		ViperMustBindPFlag("interactive", cmd.Flags().Lookup("interactive"))
	}
}

func AddPrintJSONFlag(cmd *cobra.Command) func() {
	cmd.Flags().Bool("json", false, "Print output as JSON")
	return func() {
		ViperMustBindPFlag("print-json", cmd.Flags().Lookup("json"))
	}
}

func AddProjectDirFlag(cmd *cobra.Command) func() {
	cmd.Flags().String("project-dir", "",
		"The project root which is the parent for all the project sources.\n"+
			"Defaults to the directory containing the cifuzz.yaml.")
	return func() {
		ViperMustBindPFlag("project-dir", cmd.Flags().Lookup("project-dir"))
	}
}

func AddSeedCorpusFlag(cmd *cobra.Command) func() {
	// TODO(afl): Also link to https://aflplus.plus/docs/fuzzing_in_depth/#a-collecting-inputs
	cmd.Flags().StringArrayP("seed-corpus", "s", nil,
		"A `directory` containing sample inputs for the code under test,\n"+
			"which is used in addition to inputs found in <fuzz test>_inputs.\n"+
			"See https://github.com/CodeIntelligenceTesting/cifuzz/blob/main/docs/Glossary.md#seed-corpus.\n"+
			"This flag can be used multiple times.")
	return func() {
		ViperMustBindPFlag("seed-corpus-dirs", cmd.Flags().Lookup("seed-corpus"))
	}
}

func AddTimeoutFlag(cmd *cobra.Command) func() {
	cmd.Flags().Duration("timeout", 0,
		"Maximum time to run the fuzz test, e.g. \"30m\", \"1h\". The default is to run indefinitely.")
	return func() {
		ViperMustBindPFlag("timeout", cmd.Flags().Lookup("timeout"))
	}
}

func AddUseSandboxFlag(cmd *cobra.Command) func() {
	cmd.Flags().Bool("use-sandbox", false,
		"By default, fuzz tests are executed in a sandbox to prevent accidental damage to the system.\n"+
			"Use --use-sandbox=false to run the fuzz test unsandboxed.\n"+
			"Only supported on Linux.")
	viper.SetDefault("use-sandbox", runtime.GOOS == "linux")
	return func() {
		ViperMustBindPFlag("use-sandbox", cmd.Flags().Lookup("use-sandbox"))
	}
}
