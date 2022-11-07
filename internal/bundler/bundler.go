package bundler

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/otiai10/copy"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"golang.org/x/exp/maps"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/internal/build/bazel"
	"code-intelligence.com/cifuzz/internal/build/cmake"
	"code-intelligence.com/cifuzz/internal/build/other"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/artifact"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runfiles"
	"code-intelligence.com/cifuzz/pkg/vcs"
	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/sliceutil"
)

// The (possibly empty) directory inside the fuzzing artifact archive that will be the fuzzers working directory.
const fuzzerWorkDirPath = "work_dir"

type configureVariant struct {
	Engine     string
	Sanitizers []string
}

// Runtime dependencies of fuzz tests that live under these paths will not be included in the artifact archive and have
// to be provided by the Docker image instead.
var systemLibraryPaths = map[string][]string{
	"linux": {
		"/lib",
		"/usr/lib",
	},
	"darwin": {
		"/lib",
		"/usr/lib",
	},
}

// System library dependencies that are so common that we shouldn't emit a warning for them - they will be contained in
// any reasonable Docker image.
var wellKnownSystemLibraries = map[string][]*regexp.Regexp{
	"linux": {
		versionedLibraryRegexp("ld-linux-x86-64.so"),
		versionedLibraryRegexp("libc.so"),
		versionedLibraryRegexp("libgcc_s.so"),
		versionedLibraryRegexp("libm.so"),
		versionedLibraryRegexp("libstdc++.so"),
	},
}

func versionedLibraryRegexp(unversionedBasename string) *regexp.Regexp {
	return regexp.MustCompile(".*/" + regexp.QuoteMeta(unversionedBasename) + "[.0-9]*")
}

type Opts struct {
	Branch         string        `mapstructure:"branch"`
	BuildCommand   string        `mapstructure:"build-command"`
	BuildSystem    string        `mapstructure:"build-system"`
	NumBuildJobs   uint          `mapstructure:"build-jobs"`
	Commit         string        `mapstructure:"commit"`
	Dictionary     string        `mapstructure:"dict"`
	DockerImage    string        `mapstructure:"docker-image"`
	EngineArgs     []string      `mapstructure:"engine-args"`
	Env            []string      `mapstructure:"env"`
	SeedCorpusDirs []string      `mapstructure:"seed-corpus-dirs"`
	Timeout        time.Duration `mapstructure:"timeout"`
	ProjectDir     string        `mapstructure:"project-dir"`
	ConfigDir      string        `mapstructure:"config-dir"`

	// Fields which are not configurable via viper (i.e. via cifuzz.yaml
	// and CIFUZZ_* environment variables), by setting
	// mapstructure:"-"
	FuzzTests  []string  `mapstructure:"-"`
	OutputPath string    `mapstructure:"-"`
	Stdout     io.Writer `mapstructure:"-"`
	Stderr     io.Writer `mapstructure:"-"`
}

func (opts *Opts) Validate() error {
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

	if opts.BuildSystem == config.BuildSystemBazel {
		// We don't support building a bundle with bazel without any
		// specified fuzz tests
		if len(opts.FuzzTests) == 0 {
			msg := `At least one <fuzz test> argument must be provided`
			return cmdutils.WrapIncorrectUsageError(errors.New(msg))
		}

		// Evaluate any target patterns which users might have provided
		patterns := opts.FuzzTests
		opts.FuzzTests, err = cmdutils.EvaluateBazelTargetPatterns(patterns)
		if err != nil {
			return err
		}

		if len(opts.FuzzTests) == 0 {
			err := errors.Errorf("No valid targets found for patterns: %s", strings.Join(patterns, " "))
			log.Error(err)
			return cmdutils.WrapSilentError(err)
		}
	}

	if opts.BuildSystem == config.BuildSystemOther {
		// To build with other build systems, a build command must be provided
		if opts.BuildCommand == "" {
			msg := "Flag \"build-command\" must be set when using build system type \"other\""
			return cmdutils.WrapIncorrectUsageError(errors.New(msg))
		}
		// To build with other build systems, the fuzz tests need to be
		// specified (because there is no way for us to figure out which
		// fuzz tests exist).
		if len(opts.FuzzTests) == 0 {
			msg := `At least one <fuzz test> argument must be provided when using the build
system type "other"`
			return cmdutils.WrapIncorrectUsageError(errors.New(msg))
		}
	}

	if opts.Timeout != 0 && opts.Timeout < time.Second {
		msg := fmt.Sprintf("invalid argument %q for \"--timeout\" flag: timeout can't be less than a second", opts.Timeout)
		return cmdutils.WrapIncorrectUsageError(errors.New(msg))
	}

	// If an env var doesn't contain a "=", it means the user wants to
	// use the value from the current environment
	var env []string
	for _, e := range opts.Env {
		if strings.Contains(e, "=") {
			// The environment variable contains a "=", so we use it
			env = append(env, e)
			continue
		}
		if os.Getenv(e) == "" {
			// The variable does not contain a "=" and is not set in the
			// current environment, so we ignore it
			continue
		}
		// Use the variable with the value from the current environment
		env = append(env, fmt.Sprintf("%s=%s", e, os.Getenv(e)))
	}
	opts.Env = env

	return nil
}

type Bundler struct {
	Opts    *Opts
	tempDir string
}

func NewBundler(opts *Opts) *Bundler {
	return &Bundler{Opts: opts}
}

func (b *Bundler) Bundle() error {
	var err error
	b.tempDir, err = os.MkdirTemp("", "cifuzz-bundle-")
	if err != nil {
		return errors.WithStack(err)
	}
	defer fileutil.Cleanup(b.tempDir)

	depsOk, err := b.checkDependencies()
	if err != nil {
		return err
	}
	if !depsOk {
		return dependencies.Error()
	}

	// TODO: Do not hardcode these values.
	sanitizers := []string{"address"}
	// UBSan is not supported by MSVC
	// TODO: Not needed anymore when sanitizers are configurable,
	//       then we do want to fail if the user explicitly asked for
	//       UBSan.
	if runtime.GOOS != "windows" {
		sanitizers = append(sanitizers, "undefined")
	}

	allVariantBuildResults, err := b.buildAllVariants()
	if err != nil {
		return err
	}

	// Add all fuzz test artifacts to the archive. There will be one "Fuzzer" metadata object for each pair of fuzz test
	// and Builder instance.
	var fuzzers []*artifact.Fuzzer
	archiveManifest := make(map[string]string)
	deduplicatedSystemDeps := make(map[string]struct{})
	for _, buildResults := range allVariantBuildResults {
		for _, buildResult := range buildResults {
			fuzzTestFuzzers, fuzzTestArchiveManifest, systemDeps, err := b.assembleArtifacts(buildResult)
			if err != nil {
				return err
			}
			fuzzers = append(fuzzers, fuzzTestFuzzers...)
			for _, systemDep := range systemDeps {
				deduplicatedSystemDeps[systemDep] = struct{}{}
			}
			// Produce an error when artifacts for different fuzzers conflict - this should never happen as
			// assembleArtifacts is expected to add a unique prefix for each fuzz test.
			for archivePath, absPath := range fuzzTestArchiveManifest {
				existingAbsPath, conflict := archiveManifest[archivePath]
				if conflict {
					return errors.Errorf("conflict for archive path %q: %q and %q", archivePath, existingAbsPath, absPath)
				}
				archiveManifest[archivePath] = absPath
			}
			if b.Opts.OutputPath == "" {
				if len(b.Opts.FuzzTests) == 1 {
					b.Opts.OutputPath = filepath.Base(buildResult.Executable) + ".tar.gz"
				} else {
					b.Opts.OutputPath = "fuzz_tests.tar.gz"
				}
			}
		}
	}
	systemDeps := maps.Keys(deduplicatedSystemDeps)
	sort.Strings(systemDeps)

	// Create and add the top-level metadata file.
	metadata := &artifact.Metadata{
		Fuzzers: fuzzers,
		RunEnvironment: &artifact.RunEnvironment{
			Docker: b.Opts.DockerImage,
		},
		CodeRevision: b.getCodeRevision(),
	}
	metadataYamlContent, err := metadata.ToYaml()
	if err != nil {
		return err
	}
	metadataYamlPath := filepath.Join(b.tempDir, artifact.MetadataFileName)
	err = os.WriteFile(metadataYamlPath, metadataYamlContent, 0644)
	if err != nil {
		return errors.Wrapf(err, "failed to write %s", artifact.MetadataFileName)
	}
	archiveManifest[artifact.MetadataFileName] = metadataYamlPath

	// The fuzzing artifact archive spec requires this directory even if it is empty.
	workDirPath := filepath.Join(b.tempDir, fuzzerWorkDirPath)
	err = os.Mkdir(workDirPath, 0755)
	if err != nil {
		return errors.WithStack(err)
	}
	archiveManifest[fuzzerWorkDirPath] = workDirPath

	archive, err := os.Create(b.Opts.OutputPath)
	if err != nil {
		return errors.Wrap(err, "failed to create fuzzing artifact archive")
	}
	archiveWriter := bufio.NewWriter(archive)
	defer archiveWriter.Flush()
	err = artifact.WriteArchive(archiveWriter, archiveManifest)
	if err != nil {
		return errors.Wrap(err, "failed to write fuzzing artifact archive")
	}

	log.Successf("Successfully created artifact: %s", b.Opts.OutputPath)
	if len(systemDeps) != 0 {
		log.Warnf(`The following system libraries are not part of the artifact and have to be provided by the Docker image %q:
  %s`, metadata.RunEnvironment.Docker, strings.Join(systemDeps, "\n  "))
	}
	return nil
}

func (b *Bundler) buildAllVariants() ([]map[string]*build.Result, error) {
	fuzzingVariant := configureVariant{
		// TODO: Do not hardcode these values.
		Engine:     "libfuzzer",
		Sanitizers: []string{"address"},
	}
	// UBSan is not supported by MSVb.
	// TODO: Not needed anymore when sanitizers are configurable,
	//       then we do want to fail if the user explicitly asked for
	//       UBSan.
	if runtime.GOOS != "windows" {
		fuzzingVariant.Sanitizers = append(fuzzingVariant.Sanitizers, "undefined")
	}
	configureVariants := []configureVariant{fuzzingVariant}

	// Coverage builds are not supported by MSVb.
	if runtime.GOOS != "windows" {
		coverageVariant := configureVariant{
			Engine:     "libfuzzer",
			Sanitizers: []string{"coverage"},
		}
		configureVariants = append(configureVariants, coverageVariant)
	}

	switch b.Opts.BuildSystem {
	case config.BuildSystemBazel:
		return b.buildAllVariantsBazel(configureVariants)
	case config.BuildSystemCMake:
		return b.buildAllVariantsCMake(configureVariants)
	case config.BuildSystemOther:
		return b.buildAllVariantsOther(configureVariants)
	default:
		// We panic here instead of returning an error because it's a
		// programming error if this function was called with an
		// unsupported build system, that case should have been handled
		// in the Opts.Validate function.
		panic(fmt.Sprintf("Unsupported build system: %v", b.Opts.BuildSystem))
	}
}

func (b *Bundler) buildAllVariantsBazel(configureVariants []configureVariant) ([]map[string]*build.Result, error) {
	var allResults []map[string]*build.Result
	for i, variant := range configureVariants {
		builder, err := bazel.NewBuilder(&bazel.BuilderOptions{
			ProjectDir: b.Opts.ProjectDir,
			Engine:     "libfuzzer",
			NumJobs:    b.Opts.NumBuildJobs,
			Stdout:     b.Opts.Stdout,
			Stderr:     b.Opts.Stderr,
			TempDir:    b.tempDir,
			Verbose:    viper.GetBool("verbose"),
		})
		if err != nil {
			return nil, err
		}

		b.printBuildingMsg(variant, i)

		if len(b.Opts.FuzzTests) == 0 {
			// We panic here instead of returning an error because it's a
			// programming error if this function was called without any
			// fuzz tests, that case should have been handled in the
			// Opts.Validate function.
			panic("No fuzz tests specified")
		}

		results, err := builder.BuildForBundle(variant.Engine, variant.Sanitizers, b.Opts.FuzzTests)
		if err != nil {
			return nil, err
		}
		allResults = append(allResults, results)
	}

	return allResults, nil
}

func (b *Bundler) buildAllVariantsCMake(configureVariants []configureVariant) ([]map[string]*build.Result, error) {
	var allVariantBuildResults []map[string]*build.Result
	for i, variant := range configureVariants {
		builder, err := cmake.NewBuilder(&cmake.BuilderOptions{
			ProjectDir: b.Opts.ProjectDir,
			Engine:     variant.Engine,
			Sanitizers: variant.Sanitizers,
			Parallel: cmake.ParallelOptions{
				Enabled: viper.IsSet("build-jobs"),
				NumJobs: b.Opts.NumBuildJobs,
			},
			Stdout:          b.Opts.Stdout,
			Stderr:          b.Opts.Stderr,
			FindRuntimeDeps: true,
		})
		if err != nil {
			return nil, err
		}

		b.printBuildingMsg(variant, i)

		err = builder.Configure()
		if err != nil {
			return nil, err
		}

		var fuzzTests []string
		if len(b.Opts.FuzzTests) == 0 {
			fuzzTests, err = builder.ListFuzzTests()
			if err != nil {
				return nil, err
			}
		} else {
			fuzzTests = b.Opts.FuzzTests
		}

		buildResults, err := builder.Build(fuzzTests)
		if err != nil {
			return nil, err
		}
		allVariantBuildResults = append(allVariantBuildResults, buildResults)
	}

	return allVariantBuildResults, nil
}

func (b *Bundler) printBuildingMsg(variant configureVariant, i int) {
	var typeDisplayString string
	if isCoverageBuild(variant.Sanitizers) {
		typeDisplayString = "coverage"
	} else {
		typeDisplayString = "fuzzing"
	}
	// Print a newline to separate the build logs unless this is the
	// first variant build
	if i > 0 {
		log.Print()
	}
	log.Infof("Building for %s...", typeDisplayString)
}

func (b *Bundler) buildAllVariantsOther(configureVariants []configureVariant) ([]map[string]*build.Result, error) {
	var allVariantBuildResults []map[string]*build.Result
	for i, variant := range configureVariants {
		builder, err := other.NewBuilder(&other.BuilderOptions{
			ProjectDir:   b.Opts.ProjectDir,
			BuildCommand: b.Opts.BuildCommand,
			Engine:       variant.Engine,
			Sanitizers:   variant.Sanitizers,
			Stdout:       b.Opts.Stdout,
			Stderr:       b.Opts.Stderr,
		})
		if err != nil {
			return nil, err
		}

		b.printBuildingMsg(variant, i)

		if len(b.Opts.FuzzTests) == 0 {
			// We panic here instead of returning an error because it's a
			// programming error if this function was called without any
			// fuzz tests, that case should have been handled in the
			// Opts.Validate function.
			panic("No fuzz tests specified")
		}

		buildResults := make(map[string]*build.Result)
		for _, fuzzTest := range b.Opts.FuzzTests {
			buildResult, err := builder.Build(fuzzTest)
			if err != nil {
				return nil, err
			}

			// To avoid that subsequent builds overwrite the artifacts
			// from this build, we copy them to a temporary directory
			// and adjust the paths in the build.Result struct
			tempDir := filepath.Join(b.tempDir, fuzzTestPrefix(buildResult))
			err = b.copyArtifactsToTempdir(buildResult, tempDir)
			if err != nil {
				return nil, err
			}
			buildResults[fuzzTest] = buildResult
		}
		allVariantBuildResults = append(allVariantBuildResults, buildResults)
	}

	return allVariantBuildResults, nil
}

func (b *Bundler) copyArtifactsToTempdir(buildResult *build.Result, tempDir string) error {
	fuzzTestExecutableAbsPath := buildResult.Executable
	isBelow, err := fileutil.IsBelow(fuzzTestExecutableAbsPath, buildResult.BuildDir)
	if err != nil {
		return err
	}
	if isBelow {
		relPath, err := filepath.Rel(buildResult.BuildDir, fuzzTestExecutableAbsPath)
		if err != nil {
			return errors.WithStack(err)
		}
		newExecutablePath := filepath.Join(tempDir, relPath)
		err = copy.Copy(buildResult.Executable, newExecutablePath)
		if err != nil {
			return errors.WithStack(err)
		}
		buildResult.Executable = newExecutablePath
	}

	for i, dep := range buildResult.RuntimeDeps {
		isBelow, err := fileutil.IsBelow(dep, buildResult.BuildDir)
		if err != nil {
			return err
		}
		if !isBelow {
			// If the file is not below the build dir, we assume
			// that it was not created during the build, so we
			// don't need to copy it
			continue
		}
		relPath, err := filepath.Rel(buildResult.BuildDir, dep)
		if err != nil {
			return errors.WithStack(err)
		}
		newDepPath := filepath.Join(tempDir, relPath)
		err = copy.Copy(dep, newDepPath)
		if err != nil {
			return errors.WithStack(err)
		}
		buildResult.RuntimeDeps[i] = newDepPath
	}
	buildResult.BuildDir = tempDir

	return nil
}

func (b *Bundler) checkDependencies() (bool, error) {
	deps := []dependencies.Key{dependencies.CLANG}
	if b.Opts.BuildSystem == config.BuildSystemCMake {
		deps = append(deps, dependencies.CMAKE)
	}
	return dependencies.Check(deps, dependencies.CMakeDeps, runfiles.Finder)
}

//nolint:nonamedreturns
func (b *Bundler) assembleArtifacts(buildResult *build.Result) (
	fuzzers []*artifact.Fuzzer,
	archiveManifest map[string]string,
	systemDeps []string,
	err error,
) {
	fuzzTestExecutableAbsPath := buildResult.Executable

	archiveManifest = make(map[string]string)
	// Add all build artifacts under a subdirectory of the fuzz test base path so that these files don't clash with
	// seeds and dictionaries.
	buildArtifactsPrefix := filepath.Join(fuzzTestPrefix(buildResult), "bin")

	// Add the fuzz test executable.
	ok, err := fileutil.IsBelow(fuzzTestExecutableAbsPath, buildResult.BuildDir)
	if err != nil {
		return
	}
	if !ok {
		err = errors.Errorf("fuzz test executable (%s) is not below build directory (%s)", fuzzTestExecutableAbsPath, buildResult.BuildDir)
		return
	}
	fuzzTestExecutableRelPath, err := filepath.Rel(buildResult.BuildDir, fuzzTestExecutableAbsPath)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	fuzzTestArchivePath := filepath.Join(buildArtifactsPrefix, fuzzTestExecutableRelPath)
	archiveManifest[fuzzTestArchivePath] = fuzzTestExecutableAbsPath

	// On macOS, debug information is collected in a separate .dSYM file. We bundle it in to get source locations
	// resolved in stack traces.
	fuzzTestDsymAbsPath := fuzzTestExecutableAbsPath + ".dSYM"
	dsymExists, err := fileutil.Exists(fuzzTestDsymAbsPath)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	if dsymExists {
		fuzzTestDsymArchivePath := fuzzTestArchivePath + ".dSYM"
		archiveManifest[fuzzTestDsymArchivePath] = fuzzTestDsymAbsPath
	}

	// Add the runtime dependencies of the fuzz test executable.
	externalLibrariesPrefix := ""
depsLoop:
	for _, dep := range buildResult.RuntimeDeps {
		var isBelowBuildDir bool
		isBelowBuildDir, err = fileutil.IsBelow(dep, buildResult.BuildDir)
		if err != nil {
			return
		}
		if isBelowBuildDir {
			var buildDirRelPath string
			buildDirRelPath, err = filepath.Rel(buildResult.BuildDir, dep)
			if err != nil {
				err = errors.WithStack(err)
				return
			}
			archiveManifest[filepath.Join(buildArtifactsPrefix, buildDirRelPath)] = dep
			continue
		}

		// The runtime dependency is not built as part of the current project. It will be of one of the following types:
		// 1. A standard system library that is available in all reasonable Docker images.
		// 2. A more uncommon system library that may require additional packages to be installed (e.g. X11), but still
		//    lives in a standard system library directory (e.g. /usr/lib). Such dependencies are expected to be
		//    provided by the Docker image used as the run environment.
		// 3. Any other external dependency (e.g. a CMake target imported from another CMake project with a separate
		//    build directory). These are not expected to be part of the Docker image and thus added to the archive
		//    in a special directory that is added to the library search path at runtime.

		// 1. is handled by ignoring these runtime dependencies.
		for _, wellKnownSystemLibrary := range wellKnownSystemLibraries[runtime.GOOS] {
			if wellKnownSystemLibrary.MatchString(dep) {
				continue depsLoop
			}
		}

		// 2. is handled by returning a list of these libraries that is shown to the user as a warning about the
		// required contents of the Docker image specified as the run environment.
		for _, systemLibraryPath := range systemLibraryPaths[runtime.GOOS] {
			var isBelowLibPath bool
			isBelowLibPath, err = fileutil.IsBelow(dep, systemLibraryPath)
			if err != nil {
				return
			}
			if isBelowLibPath {
				systemDeps = append(systemDeps, dep)
				continue depsLoop
			}
		}

		// 3. is handled by staging the dependency in a special external library directory in the archive that is added
		// to the library search path in the run environment.
		// Note: Since all libraries are placed in a single directory, we have to ensure that basenames of external
		// libraries are unique. If they aren't, we report a conflict.
		externalLibrariesPrefix = filepath.Join(fuzzTestPrefix(buildResult), "external_libs")
		archivePath := filepath.Join(externalLibrariesPrefix, filepath.Base(dep))
		if conflictingDep, hasConflict := archiveManifest[archivePath]; hasConflict {
			err = errors.Errorf(
				"fuzz test %q has conflicting runtime dependencies: %s and %s",
				buildResult.Name,
				dep,
				conflictingDep,
			)
			return
		}
		archiveManifest[archivePath] = dep
	}

	// Add dictionary to archive
	var archiveDict string
	if b.Opts.Dictionary != "" {
		archiveDict = filepath.Join(fuzzTestPrefix(buildResult), "dict")
		archiveManifest[archiveDict] = b.Opts.Dictionary
	}

	// Add seeds from user-specified seed corpus dirs (if any) and the
	// default seed corpus (if it exists) to the seeds directory in the
	// archive
	seedCorpusDirs := b.Opts.SeedCorpusDirs
	exists, err := fileutil.Exists(buildResult.SeedCorpus)
	if err != nil {
		return
	}
	if exists {
		seedCorpusDirs = append([]string{buildResult.SeedCorpus}, seedCorpusDirs...)
	}
	var archiveSeedsDir string
	if len(seedCorpusDirs) > 0 {
		archiveSeedsDir = filepath.Join(fuzzTestPrefix(buildResult), "seeds")
		var targetDirs []string
		for _, sourceDir := range seedCorpusDirs {
			// Put the seeds into subdirectories of the "seeds" directory
			// to avoid seeds with the same name to override each other.

			// Choose a name for the target directory which wasn't used
			// before
			basename := filepath.Join(archiveSeedsDir, filepath.Base(sourceDir))
			targetDir := basename
			i := 1
			for sliceutil.Contains(targetDirs, targetDir) {
				targetDir = fmt.Sprintf("%s-%d", basename, i)
				i++
			}
			targetDirs = append(targetDirs, targetDir)

			// Add the seeds of the seed corpus directory to the target directory
			err = artifact.AddDirToManifest(archiveManifest, targetDir, sourceDir)
			if err != nil {
				return
			}
		}
	}

	// Set NO_CIFUZZ=1 to avoid that remotely executed fuzz tests try
	// to start cifuzz
	env, err := envutil.Setenv(b.Opts.Env, "NO_CIFUZZ", "1")
	if err != nil {
		return
	}

	baseFuzzerInfo := artifact.Fuzzer{
		Target:     buildResult.Name,
		Path:       fuzzTestArchivePath,
		ProjectDir: buildResult.ProjectDir,
		Dictionary: archiveDict,
		Seeds:      archiveSeedsDir,
		EngineOptions: artifact.EngineOptions{
			Env:   env,
			Flags: b.Opts.EngineArgs,
		},
		MaxRunTime: uint(b.Opts.Timeout.Seconds()),
	}

	if externalLibrariesPrefix != "" {
		baseFuzzerInfo.LibraryPaths = []string{externalLibrariesPrefix}
	}

	if isCoverageBuild(buildResult.Sanitizers) {
		fuzzer := baseFuzzerInfo
		fuzzer.Engine = "LLVM_COV"
		// We use libFuzzer's crash-resistant merge mode. The first positional argument has to be an empty directory,
		// for which we use the working directory (empty at the beginning of a job as we include an empty work_dir in
		// the bundle). The second positional argument is the corpus directory passed in by the backend.
		// Since most libFuzzer options are not useful or potentially disruptive for coverage runs, we do not include
		// flags passed in via `--engine_args`.
		fuzzer.EngineOptions.Flags = []string{"-merge=1", "."}
		fuzzers = []*artifact.Fuzzer{&fuzzer}
		// Coverage builds are separate from sanitizer builds, so we don't have any other fuzzers to add.
		return
	}

	for _, sanitizer := range buildResult.Sanitizers {
		if sanitizer == "undefined" {
			// The artifact archive spec does not support UBSan as a standalone sanitizer.
			continue
		}
		fuzzer := baseFuzzerInfo
		fuzzer.Engine = "LIBFUZZER"
		fuzzer.Sanitizer = strings.ToUpper(sanitizer)
		fuzzers = append(fuzzers, &fuzzer)
	}

	return
}

func (b *Bundler) getCodeRevision() *artifact.CodeRevision {
	var err error
	var gitCommit string
	var gitBranch string

	if b.Opts.Commit == "" {
		gitCommit, err = vcs.GitCommit()
		if err != nil {
			log.Debugf("failed to get Git commit: %+v", err)
			return nil
		}
	} else {
		gitCommit = b.Opts.Commit
	}

	if b.Opts.Branch == "" {
		gitBranch, err = vcs.GitBranch()
		if err != nil {
			log.Debugf("failed to get Git branch: %+v", err)
			return nil
		}
	} else {
		gitBranch = b.Opts.Branch
	}

	if vcs.GitIsDirty() {
		log.Warnf("The Git repository has uncommitted changes. Archive metadata may be inaccurate.")
	}

	return &artifact.CodeRevision{
		Git: &artifact.GitRevision{
			Commit: gitCommit,
			Branch: gitBranch,
		},
	}
}

// fuzzTestPrefix returns the path in the resulting artifact archive under which fuzz test specific files should be
// added.
func fuzzTestPrefix(buildResult *build.Result) string {
	sanitizerSegment := strings.Join(buildResult.Sanitizers, "+")
	if sanitizerSegment == "" {
		sanitizerSegment = "none"
	}
	engine := buildResult.Engine
	if isCoverageBuild(buildResult.Sanitizers) {
		// The backend currently only passes the corpus directory (rather than the files contained in it) as
		// an argument to the coverage binary if it finds the substring "replayer/coverage" in the fuzz test archive
		// path.
		// FIXME: Remove this workaround as soon as the artifact spec provides a way to specify compatibility with
		//  directory arguments.
		engine = "replayer"
	}
	return filepath.Join(engine, sanitizerSegment, buildResult.Name)
}

func isCoverageBuild(sanitizers []string) bool {
	return len(sanitizers) == 1 && sanitizers[0] == "coverage"
}
