package init

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/fileutil"
)

//go:embed instructions/bazel
var bazelSetup string

//go:embed instructions/cmake
var cmakeSetup string

//go:embed instructions/maven
var mavenSetup string

//go:embed instructions/gradle
var gradleSetup string

//go:embed instructions/gradlekotlin
var gradleKotlinSetup string

type Options struct {
	Dir string
}

func New() *cobra.Command {
	return NewWithOptions(&Options{})
}

func NewWithOptions(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Set up a project for use with cifuzz",
		Long: `This command sets up a project for use with cifuzz, creating a
'cifuzz.yaml' config file.`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if opts.Dir == "" {
				opts.Dir, err = os.Getwd()
				if err != nil {
					return errors.WithStack(err)
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(opts)
		},
	}

	cmdutils.DisableConfigCheck(cmd)

	return cmd
}

func run(opts *Options) error {
	setUpAndMentionBuildSystemIntegrations(opts.Dir)

	log.Debugf("Creating config file in directory: %s", opts.Dir)
	configpath, err := config.CreateProjectConfig(opts.Dir)
	if err != nil {
		// explicitly inform the user about an existing config file
		if errors.Is(err, os.ErrExist) && configpath != "" {
			log.Warnf("Config already exists in %s", configpath)
			err = cmdutils.ErrSilent
		}
		log.Error(err, "Failed to create config")
		return err
	}
	log.Successf("Configuration saved in %s", fileutil.PrettifyPath(configpath))

	log.Print(`
Use 'cifuzz create' to create your first fuzz test.`)
	return nil
}

func setUpAndMentionBuildSystemIntegrations(dir string) {
	// Printing build system instructions is best-effort: Do not fail on errors.
	buildSystem, err := config.DetermineBuildSystem(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Debug(err)
		}
		return
	}

	switch buildSystem {
	case config.BuildSystemBazel:
		log.Print(fmt.Sprintf(bazelSetup, dependencies.RulesFuzzingHTTPArchiveRule, dependencies.CIFuzzBazelCommit))
	case config.BuildSystemCMake:
		// Note: We set NO_SYSTEM_ENVIRONMENT_PATH to avoid that the
		// system-wide cmake package takes precedence over a package
		// from a per-user installation (which is what we want, per-user
		// installations should usually take precedence over system-wide
		// installations).
		//
		// The find_package search procedure is described in
		// https://cmake.org/cmake/help/latest/command/find_package.html#config-mode-search-procedure.
		//
		// Without NO_SYSTEM_ENVIRONMENT_PATH, find_package looks in
		// paths with prefixes from the PATH environment variable in
		// step 5 (omitting any trailing "/bin").
		// The PATH usually includes "/usr/local/bin", which means that
		// find_package searches in "/usr/local/share/cifuzz" in this
		// step, which is the path we use for a system-wide installation.
		//
		// The per-user directory is searched in step 6.
		//
		// With NO_SYSTEM_ENVIRONMENT_PATH, the system-wide installation
		// directory is only searched in step 7.
		log.Print(cmakeSetup)
	case config.BuildSystemMaven:
		log.Print(mavenSetup)
	case config.BuildSystemGradle:
		kts, _ := fileutil.Exists(filepath.Join(dir, "build.gradle.kts"))
		if kts {
			log.Print(gradleKotlinSetup)
		} else {
			log.Print(gradleSetup)
		}
	}
}
