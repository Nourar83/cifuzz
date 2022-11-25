package bazel

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/internal/build/bazel"
	"code-intelligence.com/cifuzz/internal/cmd/coverage/summary"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runfiles"
)

type CoverageOptions struct {
	FuzzTest     string
	OutputFormat string
	OutputPath   string
	ProjectDir   string
	Engine       string
	NumJobs      uint
	Stdout       io.Writer
	Stderr       io.Writer
	TempDir      string
	Verbose      bool
}

func GenerateCoverageReport(opts *CoverageOptions) (string, error) {
	var err error

	// The cc_fuzz_test rule defines multiple bazel targets: If the
	// name is "foo", it defines the targets "foo", "foo_bin", and
	// others. We need to run the "foo" target here but want to
	// allow users to specify either "foo" or "foo_bin", so we check
	// if the fuzz test name  with a "_bin" suffix removed is a valid
	// target and use that in that case.
	if strings.HasSuffix(opts.FuzzTest, "_bin") {
		trimmedLabel := strings.TrimSuffix(opts.FuzzTest, "_bin")
		cmd := exec.Command("bazel", "query", trimmedLabel)
		err = cmd.Run()
		if err == nil {
			opts.FuzzTest = trimmedLabel
		}
	}

	// To avoid part of the loading and/or analysis phase to rerun, we
	// use the same flags for all bazel commands (except for those which
	// are not supported by all bazel commands we use).
	commonFlags := []string{
		"--repo_env=CC",
		"--repo_env=CXX",
		// Don't use the LLVM from Xcode
		"--repo_env=BAZEL_USE_CPP_ONLY_TOOLCHAIN=1",
	}
	if opts.NumJobs != 0 {
		commonFlags = append(commonFlags, "--jobs", fmt.Sprint(opts.NumJobs))
	}

	// Flags which should only be used for bazel run because they are
	// not supported by the other bazel commands we use
	coverageFlags := []string{
		// Tell bazel to do an optimized build, which includes debug
		// symbols (in contrast to the default "fastbuild" compilation
		// mode which strips debug symbols).
		"--compilation_mode=opt",
		// Build with debug symbols
		"--copt", "-g",
		// Disable source fortification, which is currently not supported
		// in combination with ASan, see https://github.com/google/sanitizers/issues/247
		"--copt", "-U_FORTIFY_SOURCE",
		// Build with the rules_fuzzing replayer
		"--@rules_fuzzing//fuzzing:cc_engine=@rules_fuzzing//fuzzing/engines:replay",
		"--@rules_fuzzing//fuzzing:cc_engine_instrumentation=none",
		"--@rules_fuzzing//fuzzing:cc_engine_sanitizer=none",
		"--instrument_test_targets",
		"--combined_report=lcov",
		"--experimental_use_llvm_covmap",
		"--experimental_generate_llvm_lcov",
		"--verbose_failures",
	}
	if os.Getenv("BAZEL_SUBCOMMANDS") != "" {
		coverageFlags = append(coverageFlags, "--subcommands")
	}

	llvmCov, err := runfiles.Finder.LLVMCovPath()
	if err != nil {
		return "", err
	}
	llvmProfData, err := runfiles.Finder.LLVMProfDataPath()
	if err != nil {
		return "", err
	}
	commonFlags = append(commonFlags,
		"--repo_env=BAZEL_USE_LLVM_NATIVE_COVERAGE=1",
		"--repo_env=BAZEL_LLVM_COV="+llvmCov,
		"--repo_env=BAZEL_LLVM_PROFDATA="+llvmProfData,
		"--repo_env=GCOV="+llvmProfData,
	)

	args := []string{"coverage"}
	args = append(args, commonFlags...)
	args = append(args, coverageFlags...)
	args = append(args, opts.FuzzTest)

	cmd := exec.Command("bazel", args...)
	// Redirect the build command's stdout to stderr to only have
	// reports printed to stdout
	cmd.Stdout = opts.Stderr
	cmd.Stderr = opts.Stderr
	cmd.Env, err = build.CommonBuildEnv()
	if err != nil {
		return "", err
	}
	log.Debugf("Command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		// It's expected that bazel might fail due to user configuration,
		// so we print the error without the stack trace.
		err = cmdutils.WrapExecError(errors.WithStack(err), cmd)
		log.Error(err)
		return "", cmdutils.ErrSilent
	}

	// Get the path of the created lcov report
	cmd = exec.Command("bazel", "info", "output_path")
	out, err := cmd.Output()
	if err != nil {
		// It's expected that bazel might fail due to user configuration,
		// so we print the error without the stack trace.
		err = cmdutils.WrapExecError(errors.WithStack(err), cmd)
		log.Error(err)
		return "", cmdutils.ErrSilent
	}
	bazelOutputDir := strings.TrimSpace(string(out))
	lcovReport := filepath.Join(bazelOutputDir, "_coverage", "_coverage_report.dat")

	log.Debugf("Parsing lcov report %s", lcovReport)
	lcovReportContent, err := os.ReadFile(lcovReport)
	if err != nil {
		return "", errors.WithStack(err)
	}
	summary.ParseLcov(string(lcovReportContent)).PrintTable(opts.Stderr)

	if opts.OutputFormat == "lcov" {
		if opts.OutputPath == "" {
			path, err := bazel.PathFromLabel(opts.FuzzTest, commonFlags)
			if err != nil {
				return "", err
			}
			name := strings.ReplaceAll(path, "/", "-")
			opts.OutputPath = name + ".coverage.lcov"
		}
		// We don't use copy.Copy here to be able to set the permissions
		// to 0o644 before umask - copy.Copy just copies the permissions
		// from the source file, which has permissions 555 like all
		// files created by bazel.
		content, err := os.ReadFile(lcovReport)
		if err != nil {
			return "", errors.WithStack(err)
		}
		err = os.WriteFile(opts.OutputPath, content, 0o644)
		if err != nil {
			return "", errors.WithStack(err)
		}
		return opts.OutputPath, nil
	}

	// If no output path was specified, create the coverage report in a
	// temporary directory
	if opts.OutputPath == "" {
		outputDir, err := os.MkdirTemp("", "coverage-")
		if err != nil {
			return "", errors.WithStack(err)
		}
		path, err := bazel.PathFromLabel(opts.FuzzTest, commonFlags)
		if err != nil {
			return "", err
		}
		opts.OutputPath = filepath.Join(outputDir, path)
	}

	// Create an HTML report via genhtml
	genHTML, err := runfiles.Finder.GenHTMLPath()
	if err != nil {
		return "", err
	}
	cmd = exec.Command(genHTML, "--output", opts.OutputPath, lcovReport)
	cmd.Dir = opts.ProjectDir
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return "", errors.WithStack(err)
	}

	return opts.OutputPath, nil
}
