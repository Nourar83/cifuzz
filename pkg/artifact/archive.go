package artifact

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/archiveutil"
	"code-intelligence.com/cifuzz/util/fileutil"
)

// ArchiveWriter provides functions to create a gzip-compressed tar archive.
type ArchiveWriter struct {
	*tar.Writer
	manifest   map[string]string
	gzipWriter *gzip.Writer
}

func NewArchiveWriter(w io.Writer) *ArchiveWriter {
	gzipWriter := gzip.NewWriter(w)
	return &ArchiveWriter{
		Writer:     tar.NewWriter(gzipWriter),
		manifest:   make(map[string]string),
		gzipWriter: gzipWriter,
	}
}

// Close closes the tar writer and the gzip writer. It does not close
// the underlying io.Writer.
func (w *ArchiveWriter) Close() error {
	var err error
	err = w.Writer.Close()
	if err != nil {
		return errors.WithStack(err)
	}
	err = w.gzipWriter.Close()
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// WriteFile writes the contents of sourcePath to the archive, with the
// filename archivePath (so when the archive is extracted, the file will
// be created at archivePath). Symlinks will be followed.
// WriteFile only handles regular files and symlinks.
func (w *ArchiveWriter) WriteFile(archivePath string, sourcePath string) error {
	if fileutil.IsDir(sourcePath) {
		return errors.Errorf("file is a directory: %s", sourcePath)
	}
	return w.writeFileOrEmptyDir(archivePath, sourcePath)
}

// writeFileOrEmptyDir does the same as WriteFile but doesn't return an
// error when passed a directory. If passed a directory, it creates an
// empty directory at archivePath.
func (w *ArchiveWriter) writeFileOrEmptyDir(archivePath string, sourcePath string) error {
	existingAbsPath, conflict := w.manifest[archivePath]
	if conflict {
		if existingAbsPath == sourcePath {
			log.Debugf("Skipping file %q, was already added to the archive", sourcePath)
		} else {
			return errors.Errorf("archive path %q has two source files: %q and %q", archivePath, existingAbsPath, sourcePath)
		}
	}

	f, err := os.Open(sourcePath)
	if err != nil {
		return errors.WithStack(err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return errors.WithStack(err)
	}

	// Since os.File.Stat() follows symlinks, info will not be of type symlink
	// at this point - no need to pass in a non-empty value for link.
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return errors.WithStack(err)
	}
	header.Name = archivePath
	err = w.WriteHeader(header)
	if err != nil {
		return errors.WithStack(err)
	}

	if info.IsDir() {
		return nil
	}
	if !info.Mode().IsRegular() {
		return errors.Errorf("not a regular file: %s", sourcePath)
	}

	_, err = io.Copy(w.Writer, f)
	if err != nil {
		return errors.Wrapf(err, "failed to add file to archive: %s", sourcePath)
	}

	w.manifest[archivePath] = sourcePath
	return nil
}

// WriteHardLink adds a hard link header to the archive. When the
// archive is extracted, a hard link to target with the name linkname is
// created.
func (w *ArchiveWriter) WriteHardLink(target string, linkname string) error {
	existingAbsPath, conflict := w.manifest[linkname]
	if conflict {
		return errors.Errorf("conflict for archive path %q: %q and %q", target, existingAbsPath, linkname)
	}

	header := &tar.Header{
		Typeflag: tar.TypeLink,
		Name:     linkname,
		Linkname: target,
	}
	err := w.WriteHeader(header)
	if err != nil {
		return errors.WithStack(err)
	}
	w.manifest[target] = linkname
	return nil
}

// WriteDir traverses sourceDir recursively and writes all regular files
// and symlinks to the archive.
func (w *ArchiveWriter) WriteDir(archiveBasePath string, sourceDir string) error {
	return filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return errors.WithStack(err)
		}
		archivePath := filepath.Join(archiveBasePath, relPath)

		// There is no harm in creating tar entries for empty directories, even though they are not necessary.
		return w.writeFileOrEmptyDir(archivePath, path)
	})
}

func (w *ArchiveWriter) GetSourcePath(archivePath string) string {
	return w.manifest[archivePath]
}

func (w *ArchiveWriter) HasFileEntry(archivePath string) bool {
	_, exists := w.manifest[archivePath]
	return exists
}

// ExtractArchiveForTestsOnly extracts the gzip-compressed tar archive
// bundle into dir.
func ExtractArchiveForTestsOnly(bundle, dir string) error {
	f, err := os.Open(bundle)
	if err != nil {
		return errors.WithStack(err)
	}
	gr, err := gzip.NewReader(f)
	if err != nil {
		return errors.WithStack(err)
	}
	defer gr.Close()
	return archiveutil.Untar(gr, dir)
}
