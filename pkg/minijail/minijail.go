package minijail

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runfiles"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

const (
	// Mount flags as defined in golang.org/x/sys/unix. We're not using
	// that package because it's not available on macOS.
	MS_RDONLY      = 0x1
	MS_NOSUID      = 0x2
	MS_NODEV       = 0x4
	MS_BIND        = 0x1000
	MS_REC         = 0x4000
	MS_STRICTATIME = 0x1000000
)

type WritableOption int

const (
	ReadOnly WritableOption = iota
	ReadWrite
)

type Binding struct {
	Source   string
	Target   string
	Writable WritableOption
}

func (b *Binding) String() string {
	if b.Target == "" {
		b.Target = b.Source
	}
	if b.Writable == ReadWrite {
		return fmt.Sprintf("%s,%s,1", b.Source, b.Target)
	}
	// Don't use a short form if the source or target contain a comma,
	// which would be interpreted as separators by minijail.
	if strings.ContainsRune(b.Source, ',') || strings.ContainsRune(b.Target, ',') {
		return fmt.Sprintf("%s,%s,0", b.Source, b.Target)
	}
	if b.Source != b.Target {
		return fmt.Sprintf("%s,%s", b.Source, b.Target)
	}
	return b.Source
}

var fixedMinijailArgs = []string{
	// Most of these args are the same as the ones clusterfuzz sets in
	// their minijail wrapper:
	// https://github.com/google/clusterfuzz/blob/4f8020c4c7ce73c1da0e68f04943af30bb5f0b32/src/clusterfuzz/_internal/system/minijail.py
	//
	"-U", "-m", // Quote from clusterfuzz:
	// root (uid 0 in namespace) -> USER.
	// The reason for this is that minijail does setresuid(0, 0, 0) before doing a
	// chroot, which means uid 0 needs access to the chroot dir (owned by USER).
	//
	// Note that we also run fuzzers as uid 0 (but with no capabilities in
	// permitted/effective/inherited sets which *should* mean there"s nothing
	// special about it). This is because the uid running the fuzzer also need
	// access to things owned by USER (fuzzer binaries, supporting files), and USER
	// can only be mapped once.
	"-M",      // Map current gid to root
	"-c", "0", // drop all capabilities.
	"-n", // no_new_privs
	"-v", // mount namespace
	"-p", // PID namespace
	"-l", // IPC namespace
	"-I", // Run jailed process as init.
}

var minijailConfigLines = []string{
	// Mount the whole filesystem read-only. All paths which should be
	// writable have to be added explicitly as read-write bindings.
	"mount=/,/,none," + strconv.Itoa(MS_RDONLY|MS_BIND|MS_REC),
	// Mount a new procfs on /proc
	"mount=proc,/proc,proc," + strconv.Itoa(MS_RDONLY),
	// Mount a new tmpfs on /dev/shm
	"mount=tmpfs,/dev/shm,tmpfs," + strconv.Itoa(MS_NOSUID|MS_NODEV|MS_STRICTATIME) + ",mode=1777",
	// Applications generally assume that /tmp is writable, so we mount
	// a tmpfs on /tmp. The alternative would be to mount the /tmp from
	// the host read-writable, but that could cause PID file collisions.
	// Note that below, we add read-only bind-mounts for all
	// subdirectories of /tmp.
	"mount=tmpfs,/tmp,tmpfs," + strconv.Itoa(MS_NOSUID|MS_NODEV|MS_STRICTATIME) + ",mode=1777",
	// Same as for /tmp, /run and /var/run should be writable
	"mount=tmpfs,/run,tmpfs," + strconv.Itoa(MS_NOSUID|MS_NODEV|MS_STRICTATIME) + ",mode=1777",
	"mount=tmpfs,/var/run,tmpfs," + strconv.Itoa(MS_NOSUID|MS_NODEV|MS_STRICTATIME) + ",mode=1777",
	// Always log to stderr
	"logging=stderr",
}

var defaultBindings = []*Binding{
	// We allow access to /dev/null and /dev/urandom because AFL needs
	// access to them and some fuzz targets might as well (for example
	// our lighttpd example fuzz target).
	// They have to be mounted read-write, else minijail fails with
	// libminijail[1]: cannot bind-remount: [...] Operation not permitted
	{Source: "/dev/null", Writable: ReadWrite},
	{Source: "/dev/urandom", Writable: ReadWrite},
}

type Options struct {
	Args      []string
	Bindings  []*Binding
	OutputDir string
}

type minijail struct {
	*Options
	Args      []string
	chrootDir string
}

func NewMinijail(opts *Options) (*minijail, error) {
	// Evaluate symlinks in the executable path
	path, err := filepath.EvalSymlinks(opts.Args[0])
	if err != nil {
		return nil, errors.WithStack(err)
	}
	opts.Args[0] = path

	// --------------------------
	// --- Create directories ---
	// --------------------------
	// Create chroot directory
	chrootDir, err := os.MkdirTemp("", "minijail-chroot-")
	if err != nil {
		return nil, err
	}

	// Create /tmp, /proc directories.
	for _, dir := range []string{"/proc", "/tmp"} {
		err = os.MkdirAll(filepath.Join(chrootDir, dir), 0o755)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	// Create /dev/shm which is required to allow using shared memory
	err = os.MkdirAll(filepath.Join(chrootDir, "dev", "shm"), 0o755)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// ----------------------------
	// --- Set up minijail args ---
	// ----------------------------
	minijailPath, err := runfiles.Finder.Minijail0Path()
	if err != nil {
		return nil, err
	}
	minijailArgs := append([]string{minijailPath}, fixedMinijailArgs...)

	// This causes minijail to not use preload hooking, which
	// allows us to run it without the libminijailpreload.so. That has
	// two benefits:
	// * We can use a statically built minijail0 binary, avoiding runtime
	//   dependencies on libcap.
	// * It avoids that minijail0 doesn't print error messages, which
	//   happens when preloading is used.
	//
	// Note that (quoting the Minijail manual [1]): "some jailing can
	// only be achieved from the process to which they will actually
	// apply [via preloading]".
	// [1] https://google.github.io/minijail/minijail0.1.html#implementation
	//
	// Since we don't use minijail for security but only for safety
	// (i.e. we only want to protect against accidental damage done to
	// the system, like the fuzz target accidentally deleting files or
	// killing processes etc), it should be fine that the jailing is not
	// perfect.
	minijailArgs = append(minijailArgs, "-T", "static", "--ambient")

	// Change root filesystem to the chroot directory. See pivot_root(2).
	minijailArgs = append(minijailArgs, "-P", chrootDir)

	// -----------------------
	// --- Set up bindings ---
	// -----------------------
	var bindings []*Binding

	// Add bindings for all subdirectories of /tmp. These are not already
	// mounted from the host because above we mounted a tmpfs on /tmp.
	// We still want read-only bind-mounts of the subdirectories because
	// those could contain files used by the fuzz test, for example a
	// temporary project directory.
	// We don't mount top-level files of /tmp because PID files are often
	// stored there, which could lead to PID collisions with the host.
	// We add those bindings first because they can be overwritten by
	// read-write bindings in opts.Bindings.
	entries, err := os.ReadDir("/tmp")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	chrootDirFileInfo, err := os.Stat(chrootDir)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		fileInfo, err := entry.Info()
		if err != nil {
			// Skip the directory if it's not accessible
			continue
		}
		// Don't add bind-mounts for the chroot dir itself
		if os.SameFile(fileInfo, chrootDirFileInfo) {
			continue
		}
		bindings = append(bindings, &Binding{Source: "/tmp" + entry.Name()})
	}

	bindings = append(bindings, opts.Bindings...)
	bindings = append(bindings, defaultBindings...)

	// Allow read-write access to the minijail output directory
	if opts.OutputDir != "" {
		bindings = append(bindings, &Binding{Source: opts.OutputDir, Writable: ReadWrite})
	}

	// We expect the current working directory to be the artifacts
	// directory, which should be accessible to the fuzz target, so we
	// add a binding for it.
	// Some fuzz targets (e.g. the one for nginx) write to the working
	// directory, which is why we mount it read-write. We decided that
	// this is fine on CIFUZZ-1192.
	workdir, err := os.Getwd()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	bindings = append(bindings, &Binding{Source: workdir, Writable: ReadWrite})

	// Add binding for the executable
	bindings = append(bindings, &Binding{Source: path})

	// Add binding for process_wrapper. process_wrapper changes the
	// working directory and then executes the specified command.
	processWrapperPath, err := runfiles.Finder.ProcessWrapperPath()
	if err != nil {
		return nil, err
	}
	bindings = append(bindings, &Binding{Source: processWrapperPath})

	// Add bindings to the minijail config
	for _, binding := range bindings {
		if binding.Target == "" {
			binding.Target = binding.Source
		}
		// Skip if the source doesn't exist
		exists, err := fileutil.Exists(binding.Source)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}

		// Create the destination
		if fileutil.IsDir(binding.Source) {
			err = os.MkdirAll(filepath.Join(chrootDir, binding.Target), 0o755)
			if err != nil {
				return nil, errors.WithStack(err)
			}
		} else {
			err = os.MkdirAll(filepath.Join(chrootDir, filepath.Dir(binding.Target)), 0o755)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			err = fileutil.Touch(filepath.Join(chrootDir, binding.Target))
			if err != nil {
				return nil, err
			}
		}

		minijailConfigLines = append(minijailConfigLines, "bind-mount="+binding.String())
	}

	// Write the config file
	configFile := filepath.Join(chrootDir, "minijail.conf")
	configFileContent := strings.Join(append([]string{"% minijail-config-file v0"}, minijailConfigLines...), "\n")
	log.Debugf("%s:\n%s", configFile, configFileContent)
	err = os.WriteFile(configFile, []byte(configFileContent), 0700)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	minijailArgs = append(minijailArgs, "--config", configFile)

	// -----------------------------------
	// --- Set up process wrapper args ---
	// -----------------------------------
	// The process wrapper changes the working directory inside the
	// sandbox to the first argument
	processWrapperArgs := []string{processWrapperPath, workdir}

	// --------------------
	// --- Run minijail ---
	// --------------------
	args := stringutil.JoinSlices("--", minijailArgs, processWrapperArgs, opts.Args)

	// When CI_DEBUG_MINIJAIL_SLEEP_FOREVER is set, instead of executing
	// the actual command, we store it in the CMD environment variable
	// and start a shell to allow debugging issues interactively.
	if os.Getenv("CI_DEBUG_MINIJAIL_SLEEP_FOREVER") != "" {
		_ = os.MkdirAll(filepath.Join(chrootDir, "bin"), 0o755)
		minijailArgs = append(minijailArgs, "-b", "/bin")
		processWrapperArgs = append(processWrapperArgs, "CMD="+strings.Join(opts.Args, " "))
		args = stringutil.JoinSlices("--", minijailArgs, processWrapperArgs, []string{"/bin/sh"})
	}

	return &minijail{
		Options:   opts,
		chrootDir: chrootDir,
		Args:      args,
	}, nil
}

func (m *minijail) Cleanup() {
	fileutil.Cleanup(m.chrootDir)
}
