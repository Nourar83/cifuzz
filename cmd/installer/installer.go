//go:build installer

package main

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/otiai10/copy"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"

	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/installer"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/fileutil"
)

//go:embed build
var buildFiles embed.FS

var notes []string

var installBashCompletion bool
var installZshCompletion bool
var installFishCompletion bool

func main() {
	flags := pflag.NewFlagSet("cifuzz installer", pflag.ExitOnError)
	helpRequested := flags.BoolP("help", "h", false, "")
	flags.Bool("verbose", false, "Print verbose output")
	flags.BoolVar(&installBashCompletion, "bash-completion", false, "Install the bash completion script even if SHELL is not bash")
	flags.BoolVar(&installZshCompletion, "zsh-completion", false, "Install the zsh completion script even if SHELL is not zsh")
	flags.BoolVar(&installFishCompletion, "fish-completion", false, "Install the fish completion script even if SHELL is not fish")
	ignoreCheck := flags.Bool("ignore-installation-check", false, "Doesn't check if a previous installation already exists")
	cmdutils.ViperMustBindPFlag("verbose", flags.Lookup("verbose"))

	err := flags.Parse(os.Args)
	if err != nil {
		log.Error(errors.WithStack(err))
		os.Exit(1)
	}

	if *helpRequested {
		log.Printf("Usage of cifuzz installer:")
		flags.PrintDefaults()
		os.Exit(0)
	}

	if installDir, exists := oldInstallationExists(); exists && !*ignoreCheck {
		log.Warnf(
			`Old cifuzz installation exists in %s.
To prevent version issues please remove the files.
See https://github.com/CodeIntelligenceTesting/cifuzz#uninstall`,
			filepath.Join(installDir, ".."))
		os.Exit(0)
	}

	err = ExtractEmbeddedFiles(&buildFiles)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	binDir, err := installer.GetBinDir()
	if err != nil {
		log.Error(err, err.Error())
		os.Exit(1)
	}

	log.Success("Installation successful")

	// Print a newline between the "Installation successful" message
	// and the notes
	log.Print()

	for _, note := range notes {
		log.Note(note)
	}

	if runtime.GOOS == "windows" {
		// TODO: On Windows, users generally don't expect having to fiddle with their PATH. We should update it for
		//       them, but that requires asking for admin access.
		log.Notef(`Please add the following directory to your PATH:
	%s
If you haven't already done so.
`, binDir)
	} else {
		shell := filepath.Base(os.Getenv("SHELL"))
		var profileName string
		if shell == "bash" {
			profileName = "~/.bash_profile"
		} else if shell == "zsh" {
			profileName = "~/.zprofile"
		} else {
			profileName = "~/.profile"
		}
		log.Notef(`To add cifuzz to your PATH:

    export PATH="$PATH:%s" >> %s

`, binDir, profileName)
	}
}

// ExtractEmbeddedFiles extracts the embedded files that were built by
// the cifuzz builder into the installation directory and registers the
// CMake package.
func ExtractEmbeddedFiles(files *embed.FS) error {
	// List of files which have to be made executable
	cifuzzExecutable := filepath.Join("bin", "cifuzz")
	executableFiles := []string{
		cifuzzExecutable,
		filepath.Join("bin", "minijail0"),
		filepath.Join("lib", "process_wrapper"),
	}

	installDir, err := installer.GetInstallDir()
	if err != nil {
		return err
	}
	binDir, err := installer.GetBinDir()
	if err != nil {
		return err
	}

	if exists, _ := fileutil.Exists(installDir); exists {
		log.Infof("Previous installation in %s & %s will be overwritten.", installDir, binDir)
		if err = os.RemoveAll(installDir); err != nil {
			return err
		}
	}
	if err = os.RemoveAll(filepath.Join(binDir, "cifuzz")); err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		log.Printf("Installing cifuzz to %s", installDir)
	} else {
		log.Printf("Installing data files to %s", installDir)
		log.Printf("Installing executable to %s", filepath.Join(binDir, "cifuzz"))
	}

	buildFS, err := fs.Sub(files, "build")
	if err != nil {
		return errors.WithStack(err)
	}

	// Extract files from the build directory
	err = fs.WalkDir(buildFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return errors.WithStack(err)
		}

		if !d.IsDir() {
			var targetDir string
			// cifuzz executable should be in extra bin directory
			if path == cifuzzExecutable {
				targetDir = binDir
			} else {
				targetDir = filepath.Dir(filepath.Join(installDir, path))
			}

			err = os.MkdirAll(targetDir, 0755)
			if err != nil {
				return errors.WithStack(err)
			}

			content, err := fs.ReadFile(buildFS, path)
			if err != nil {
				return errors.WithStack(err)
			}

			fileName := filepath.Join(targetDir, d.Name())
			err = os.WriteFile(fileName, content, 0644)
			if err != nil {
				return errors.WithStack(err)
			}

			// Make required files executable
			for _, executableFile := range executableFiles {
				if executableFile == path {
					err = os.Chmod(fileName, 0755)
					if err != nil {
						return errors.WithStack(err)
					}
				}
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Install the autocompletion script for the current shell (if the
	// shell is supported)
	cifuzzPath := filepath.Join(binDir, "cifuzz")
	shell := filepath.Base(os.Getenv("SHELL"))
	var shellCompletionInstalled bool
	if shell == "bash" || installBashCompletion {
		err = installBashCompletionScript(installDir, cifuzzPath)
		if err != nil {
			return err
		}
		shellCompletionInstalled = true
	}
	if shell == "zsh" || installZshCompletion {
		err = installZshCompletionScript(installDir, cifuzzPath)
		if err != nil {
			return err
		}
		shellCompletionInstalled = true
	}
	if shell == "fish" || installFishCompletion {
		err = installFishCompletionScript(cifuzzPath)
		if err != nil {
			return err
		}
		shellCompletionInstalled = true
	}
	if !shellCompletionInstalled {
		log.Printf("Not installing shell completion script: Unsupported shell: %s", shell)
	}

	// Support not copying and registering the CMake package.

	// Install and register the CMake package - unless the user
	// set CIFUZZ_INSTALLER_NO_CMAKE. One use case for not installing
	// CMake is when cifuzz is installed in a sandbox which doesn't
	// allow access to the CMake packages directory.
	if os.Getenv("CIFUZZ_INSTALLER_NO_CMAKE") == "" {
		if runtime.GOOS != "windows" && os.Getuid() == 0 {
			// On non-Windows systems, CMake doesn't have the concept of a system
			// package registry. Instead, install the package into the well-known
			// prefix /usr/local using the following relative search path:
			// /(lib/|lib|share)/<name>*/(cmake|CMake)/
			// See:
			// https://cmake.org/cmake/help/latest/command/find_package.html#config-mode-search-procedure
			// https://gitlab.kitware.com/cmake/cmake/-/blob/5ed9232d781ccfa3a9fae709e12999c6649aca2f/Modules/Platform/UnixPaths.cmake#L30)
			cmakeSrc := filepath.Join(installDir, "share", "cifuzz")
			cmakeDest := "/usr/local/share/cifuzz"
			err = copy.Copy(cmakeSrc, cmakeDest)
			if err != nil {
				return errors.WithStack(err)
			}
		} else {
			// The CMake package registry entry has to point directly to the directory
			// containing the CIFuzzConfig.cmake file rather than any valid prefix for
			// the config mode search procedure.
			dirForRegistry := filepath.Join(installDir, "share", "cifuzz", "cmake")
			err = installer.RegisterCMakePackage(dirForRegistry)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func installBashCompletionScript(targetDir, cifuzzPath string) error {
	// Installing the bash completion script is only supported on Linux
	// and macOS
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil
	}

	// Install the completion script in the target directory
	completionsDir := filepath.Join(targetDir, "share", "cifuzz", "bash", "completions")
	err := os.MkdirAll(completionsDir, 0700)
	if err != nil {
		return errors.WithStack(err)
	}

	completionScriptPath := filepath.Join(completionsDir, "_cifuzz")
	cmd := exec.Command("sh", "-c", "'"+cifuzzPath+"' completion bash > \""+completionScriptPath+"\"")
	cmd.Stderr = os.Stderr
	log.Printf("Command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		return errors.WithStack(err)
	}

	switch runtime.GOOS {
	case "linux":
		var dir string
		if os.Getuid() == 0 {
			// We run as root, so we put the completion script into the
			// system-wide completions directory
			dir = "/etc/bash_completion.d"
		} else {
			// We run as non-root, so install the script to the user's
			// completions directory
			// See https://github.com/scop/bash-completion/tree/2.9#installation
			if os.Getenv("XDG_DATA_HOME") != "" {
				dir = os.Getenv("XDG_DATA_HOME") + "/bash-completion/completions"
			} else {
				dir = os.Getenv("HOME") + "/.local/share/bash-completion/completions"
			}
		}
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return errors.WithStack(err)
		}
		cmd = exec.Command("bash", "-c", "'"+cifuzzPath+"' completion bash > \""+dir+"/cifuzz\"")
		log.Printf("Command: %s", cmd.String())
		err = cmd.Run()
		if err != nil {
			return errors.WithStack(err)
		}
	case "darwin":
		// There are no bash completion directories on macOS by default,
		// so we need user action to source our installation directory
		notes = append(notes, fmt.Sprintf(`To enable command completion:

    # enable bash completion (if not already enabled):
    echo "[ -f $(brew --prefix)/etc/bash_completion ] && source $(brew --prefix)/etc/bash_completion" >> ~/.bash_profile
    # enable cifuzz completion:
    echo source '%s' >> ~/.bash_profile

`, completionScriptPath))
	}

	return nil
}

func installZshCompletionScript(targetDir, cifuzzPath string) error {
	// Installing the zsh completion script is only supported on Linux
	// and macOS
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil
	}

	// Install the completion script in the target directory
	completionsDir := filepath.Join(targetDir, "share", "cifuzz", "zsh", "completions")
	err := os.MkdirAll(completionsDir, 0700)
	if err != nil {
		return errors.WithStack(err)
	}

	completionScriptPath := filepath.Join(completionsDir, "_cifuzz")
	cmd := exec.Command("sh", "-c", "'"+cifuzzPath+"' completion zsh > \""+completionScriptPath+"\"")
	cmd.Stderr = os.Stderr
	log.Printf("Command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		return errors.WithStack(err)
	}

	// Check if we can write to the first path in the fpath, in which
	// case we also install the completion script into that directory,
	// not requiring any user action.
	//
	// We try to read $ZDOTDIR/.zshrc or ~/.zshrc here in order to
	// store the completion script in the correct directory.
	// When run as non-root, we try to get a user-writeable directory
	// from $fpath[1] by reading ~/.zshrc.
	// When run as root, it's expected that /root/.zshrc doesn't
	// exist, which leaves $fpath[1] at the default which should be only
	// writeable as root.
	cmd = exec.Command("zsh", "-c", ". ${ZDOTDIR:-${HOME}}/.zshrc 2>/dev/null; echo \"$fpath[1]\"")
	cmd.Stderr = os.Stderr
	log.Printf("Command: %s", cmd.String())
	out, err := cmd.Output()
	if err != nil {
		return errors.WithStack(err)
	}
	fpath := strings.TrimSpace(string(out))

	// Try to write the script to the first fpath directory
	cmd = exec.Command("zsh", "-c", "'"+cifuzzPath+"' completion zsh > \""+fpath+"/_cifuzz\"")
	cmd.Stderr = os.Stderr
	log.Printf("Command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		// Writing to the first fpath directory failed, so we tell the
		// user to add the completion script from our install directory
		// to their fpath instead
		notes = append(notes, fmt.Sprintf(`To enable command completion:

    echo fpath=(%s $fpath) >> ~/.zshrc
    echo "autoload -U compinit; compinit" >> ~/.zshrc

`, completionsDir))
	} else {
		notes = append(notes, `To enable command completion (if not already enabled):

    echo "autoload -U compinit; compinit" >> ~/.zshrc

`)
	}

	return nil
}

func installFishCompletionScript(cifuzzPath string) error {
	var dir string
	// Choose the correct directory for the completion script.
	// See https://fishshell.com/docs/current/completions.html#where-to-put-completions
	if os.Getuid() == 0 {
		// We run as root, so we put the completion script into the
		// system-wide completions directory
		dir = "/usr/share/fish/vendor_completions.d"
	} else {
		// We run as non-root, so install the script to the user's
		// completions directory
		if os.Getenv("XDG_DATA_HOME") != "" {
			dir = os.Getenv("XDG_DATA_HOME") + "/fish/vendor_completions.d"
		} else {
			dir = os.Getenv("HOME") + "/.local/share/fish/vendor_completions.d"
		}
	}
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return errors.WithStack(err)
	}

	cmd := exec.Command("fish", "-c", "'"+cifuzzPath+"' completion fish > \""+dir+"/cifuzz.fish\"")
	cmd.Stderr = os.Stderr
	log.Printf("Command: %s", cmd.String())
	err = cmd.Run()
	return errors.WithStack(err)
}

func oldInstallationExists() (string, bool) {
	path, err := exec.LookPath("cifuzz")
	if err != nil {
		// Ignore error since it is no problem if it can't be found
		return "", false
	}

	binDir, err := installer.GetBinDir()
	if err != nil {
		log.Error(err)
		return "", false
	}

	// We do not want to alert the user if the old version is in a directory
	// we expect (and overwrite anyway).
	//
	// It doesn't matter if there are other cifuzz installation paths in the $PATH
	// because exec.LookPath always returns the first one that it finds and ergo the
	// one that would be used when calling cifuzz
	if filepath.Dir(path) == binDir {
		return "", false
	}

	return path, true
}
