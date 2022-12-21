package bundler

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/internal/bundler/archive"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/vcs"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/sliceutil"
)

// The (possibly empty) directory inside the fuzzing artifact archive that will
// be the fuzzers working directory.
const fuzzerWorkDirPath = "work_dir"

type Bundler struct {
	opts *Opts
}

func New(opts *Opts) *Bundler {
	return &Bundler{opts: opts}
}

func (b *Bundler) Bundle() error {
	// create temp dir
	var err error
	b.opts.tempDir, err = os.MkdirTemp("", "cifuzz-bundle-")
	if err != nil {
		return errors.WithStack(err)
	}
	defer fileutil.Cleanup(b.opts.tempDir)

	var outputPath string
	if b.opts.OutputPath != "" {
		outputPath = b.opts.OutputPath
	} else if len(b.opts.FuzzTests) == 1 {
		outputPath = filepath.Base(b.opts.FuzzTests[0]) + ".tar.gz"
	} else {
		outputPath = "fuzz_tests.tar.gz"
	}

	bundle, err := os.Create(outputPath)
	if err != nil {
		return errors.Wrap(err, "failed to create fuzzing artifact archive")
	}
	bufWriter := bufio.NewWriter(bundle)
	archiveWriter := archive.NewArchiveWriter(bufWriter)

	var fuzzers []*archive.Fuzzer

	switch b.opts.BuildSystem {
	case config.BuildSystemCMake, config.BuildSystemBazel, config.BuildSystemOther:
		fuzzers, err = newLibfuzzerBundler(b.opts, archiveWriter).bundle()
	case config.BuildSystemMaven, config.BuildSystemGradle:
		fuzzers, err = newJazzerBundler(b.opts, archiveWriter).bundle()
	}
	if err != nil {
		return err
	}

	// Create and add the top-level metadata file.
	metadata := &archive.Metadata{
		Fuzzers: fuzzers,
		RunEnvironment: &archive.RunEnvironment{
			Docker: b.opts.DockerImage,
		},
		CodeRevision: b.getCodeRevision(),
	}
	metadataYamlContent, err := metadata.ToYaml()
	if err != nil {
		return err
	}
	metadataYamlPath := filepath.Join(b.opts.tempDir, archive.MetadataFileName)
	err = os.WriteFile(metadataYamlPath, metadataYamlContent, 0644)
	if err != nil {
		return errors.Wrapf(err, "failed to write %s", archive.MetadataFileName)
	}
	err = archiveWriter.WriteFile(archive.MetadataFileName, metadataYamlPath)
	if err != nil {
		return err
	}

	// The fuzzing artifact archive spec requires this directory even if it is empty.
	workDirPath := filepath.Join(b.opts.tempDir, fuzzerWorkDirPath)
	err = os.Mkdir(workDirPath, 0755)
	if err != nil {
		return errors.WithStack(err)
	}
	err = archiveWriter.WriteDir(fuzzerWorkDirPath, workDirPath)
	if err != nil {
		return err
	}

	err = archiveWriter.Close()
	if err != nil {
		return errors.WithStack(err)
	}
	err = bufWriter.Flush()
	if err != nil {
		return errors.WithStack(err)
	}
	err = bundle.Close()
	if err != nil {
		return errors.WithStack(err)
	}

	log.Successf("Successfully created bundle: %s", b.opts.OutputPath)

	return nil
}

func (b *Bundler) getCodeRevision() *archive.CodeRevision {
	var err error
	var gitCommit string
	var gitBranch string

	if b.opts.Commit == "" {
		gitCommit, err = vcs.GitCommit()
		if err != nil {
			log.Debugf("failed to get Git commit: %+v", err)
			return nil
		}
	} else {
		gitCommit = b.opts.Commit
	}

	if b.opts.Branch == "" {
		gitBranch, err = vcs.GitBranch()
		if err != nil {
			log.Debugf("failed to get Git branch: %+v", err)
			return nil
		}
	} else {
		gitBranch = b.opts.Branch
	}

	if vcs.GitIsDirty() {
		log.Warnf("The Git repository has uncommitted changes. Archive metadata may be inaccurate.")
	}

	return &archive.CodeRevision{
		Git: &archive.GitRevision{
			Commit: gitCommit,
			Branch: gitBranch,
		},
	}
}

func prepareSeeds(seedCorpusDirs []string, archiveSeedsDir string, archiveWriter *archive.ArchiveWriter) error {
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
		err := archiveWriter.WriteDir(targetDir, sourceDir)
		if err != nil {
			return err
		}
	}
	return nil
}
