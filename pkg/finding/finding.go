package finding

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alexflint/go-filemutex"
	"github.com/otiai10/copy"
	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/parser/libfuzzer/stacktrace"
	"code-intelligence.com/cifuzz/util/fileutil"
)

const NameCrashingInput = "crashing-input"
const NameJsonFile = "finding.json"
const NameFindingsDir = ".cifuzz-findings"
const lockFile = ".lock"

type Finding struct {
	Name               string        `json:"name,omitempty"`
	Type               ErrorType     `json:"type,omitempty"`
	InputData          []byte        `json:"input_data,omitempty"`
	Logs               []string      `json:"logs,omitempty"`
	Details            string        `json:"details,omitempty"`
	HumanReadableInput string        `json:"human_readable_input,omitempty"`
	MoreDetails        *ErrorDetails `json:"more_details,omitempty"`
	Tag                uint64        `json:"tag,omitempty"`
	InputFile          string

	// Note: The following fields don't exist in the protobuf
	// representation used in the Code Intelligence core repository.
	CreatedAt  time.Time                `json:"created_at,omitempty"`
	StackTrace []*stacktrace.StackFrame `json:"stack_trace,omitempty"`

	seedPath string
}

type ErrorType string

// These constants must have this exact value (in uppercase) to be able
// to parse JSON-marshalled reports as protobuf reports which use an
// enum for this field.
const (
	ErrorType_UNKNOWN_ERROR     ErrorType = "UNKNOWN_ERROR"
	ErrorType_COMPILATION_ERROR ErrorType = "COMPILATION_ERROR"
	ErrorType_CRASH             ErrorType = "CRASH"
	ErrorType_WARNING           ErrorType = "WARNING"
	ErrorType_RUNTIME_ERROR     ErrorType = "RUNTIME_ERROR"
)

type ErrorDetails struct {
	Id       string    `json:"id,omitempty"`
	Name     string    `json:"name,omitempty"`
	Severity *Severity `json:"severity,omitempty"`
}

type SeverityLevel string

const (
	SeverityLevel_CRITICAL SeverityLevel = "CRITICAL"
	SeverityLevel_HIGH     SeverityLevel = "HIGH"
	SeverityLevel_MEDIUM   SeverityLevel = "MEDIUM"
	SeverityLevel_LOW      SeverityLevel = "LOW"
)

type Severity struct {
	Level SeverityLevel `json:"description,omitempty"`
	Score float32       `json:"score,omitempty"`
}

func (f *Finding) GetDetails() string {
	if f != nil {
		return f.Details
	}
	return ""
}

func (f *Finding) GetSeedPath() string {
	if f != nil {
		return f.seedPath
	}
	return ""
}

// Exists returns whether the JSON file of this finding already exists
func (f *Finding) Exists(projectDir string) (bool, error) {
	jsonPath := filepath.Join(projectDir, NameFindingsDir, f.Name, NameJsonFile)
	return fileutil.Exists(jsonPath)
}

func (f *Finding) Save(projectDir string) error {
	findingDir := filepath.Join(projectDir, NameFindingsDir, f.Name)
	jsonPath := filepath.Join(findingDir, NameJsonFile)

	err := os.MkdirAll(findingDir, 0755)
	if err != nil {
		return errors.WithStack(err)
	}

	err = f.saveJson(jsonPath)
	if err != nil {
		return err
	}

	return nil
}

func (f *Finding) saveJson(jsonPath string) error {
	bytes, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return errors.WithStack(err)
	}

	if err := os.WriteFile(jsonPath, bytes, 0644); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// MoveInputFile copies the input file to the finding directory and
// the seed corpus directory and adjusts the finding logs accordingly.
func (f *Finding) MoveInputFile(projectDir, seedCorpusDir string) error {
	// Acquire a file lock to avoid races with other cifuzz processes
	// running in parallel
	findingDir := filepath.Join(projectDir, NameFindingsDir, f.Name)
	err := os.MkdirAll(findingDir, 0755)
	if err != nil {
		return errors.WithStack(err)
	}
	lockFile := filepath.Join(findingDir, lockFile)
	mutex, err := filemutex.New(lockFile)
	if err != nil {
		return errors.WithStack(err)
	}
	err = mutex.Lock()
	if err != nil {
		return errors.WithStack(err)
	}

	// Actually move the input file
	err = f.moveInputFile(projectDir, seedCorpusDir)

	// Release the file lock
	unlockErr := mutex.Unlock()
	if err == nil {
		return errors.WithStack(unlockErr)
	}
	if unlockErr != nil {
		log.Error(unlockErr)
	}
	return err
}

func (f *Finding) moveInputFile(projectDir, seedCorpusDir string) error {
	findingDir := filepath.Join(projectDir, NameFindingsDir, f.Name)
	path := filepath.Join(findingDir, NameCrashingInput)

	// Copy the input file to the finding dir. We don't use os.Rename to
	// avoid errors when source and target are not on the same mounted
	// filesystem.
	err := copy.Copy(f.InputFile, path)
	if err != nil {
		return errors.WithStack(err)
	}

	// Copy the input file to the seed corpus dir
	err = os.MkdirAll(seedCorpusDir, 0755)
	if err != nil {
		return errors.WithStack(err)
	}
	f.seedPath = filepath.Join(seedCorpusDir, f.Name)
	err = copy.Copy(f.InputFile, f.seedPath)
	if err != nil {
		return errors.WithStack(err)
	}

	// Remove the source which was now copied.
	err = os.Remove(f.InputFile)
	if err != nil {
		return errors.WithStack(err)
	}

	// Replace the old filename in the finding logs. Replace it with the
	// relative path to not leak the directory structure of the current
	// user in the finding logs (which might be shared with others).
	cwd, err := os.Getwd()
	if err != nil {
		return errors.WithStack(err)
	}
	relPath, err := filepath.Rel(cwd, path)
	if err != nil {
		return errors.WithStack(err)
	}
	for i, line := range f.Logs {
		f.Logs[i] = strings.ReplaceAll(line, f.InputFile, relPath)
	}
	log.Debugf("moved input file from %s to %s", f.InputFile, path)

	// The path in the InputFile field is expected to be relative to the
	// project directory
	pathRelativeToProjectDir, err := filepath.Rel(projectDir, path)
	if err != nil {
		return errors.WithStack(err)
	}
	f.InputFile = pathRelativeToProjectDir
	return nil
}

func (f *Finding) ShortDescriptionWithName() string {
	return fmt.Sprintf("[%s] %s", f.Name, f.ShortDescription())
}

func (f *Finding) ShortDescription() string {
	return strings.Join(f.ShortDescriptionColumns(), " ")
}

func (f *Finding) ShortDescriptionColumns() []string {
	var columns []string

	// TODO this is just a naive approach to get some error types.
	// This should be replace as soon as we have a list of the different error types.
	var errorType string
	switch f.Type {
	case ErrorType_CRASH:
		switch f.Details {
		case "detected memory leaks":
			errorType = f.Details
		default:
			errorType = strings.ReplaceAll(strings.Split(f.Details, " ")[0], "-", " ")
		}
	case ErrorType_RUNTIME_ERROR:
		errorType = strings.Split(f.Details, ":")[0]
	default:
		errorType = f.Details
	}

	columns = append(columns, errorType)

	// add location (file, function, line)
	if len(f.StackTrace) > 0 {
		f := f.StackTrace[0]
		var location string
		// in some cases ASan/Libfuzzer do not include the column in the stack trace
		if f.Column != 0 {
			location = fmt.Sprintf("%s:%d:%d", f.SourceFile, f.Line, f.Column)
		} else {
			location = fmt.Sprintf("%s:%d", f.SourceFile, f.Line)
		}
		columns = append(columns, fmt.Sprintf("in %s (%s)", f.Function, location))
	}
	return columns
}

// ListFindings parses the JSON files of all findings and returns the
// result.
func ListFindings(projectDir string) ([]*Finding, error) {
	findingsDir := filepath.Join(projectDir, NameFindingsDir)
	entries, err := os.ReadDir(findingsDir)
	if os.IsNotExist(err) {
		return []*Finding{}, nil
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var res []*Finding
	for _, e := range entries {
		f, err := LoadFinding(projectDir, e.Name())
		if err != nil {
			return nil, err
		}
		res = append(res, f)
	}

	// Sort the findings by date, starting with the newest
	sort.SliceStable(res, func(i, j int) bool {
		return res[i].CreatedAt.After(res[j].CreatedAt)
	})

	return res, nil
}

// LoadFinding parses the JSON file of the specified finding and returns
// the result.
// If the specified finding does not exist, a NotExistError is returned.
func LoadFinding(projectDir, findingName string) (*Finding, error) {
	findingDir := filepath.Join(projectDir, NameFindingsDir, findingName)
	jsonPath := filepath.Join(findingDir, NameJsonFile)
	bytes, err := os.ReadFile(jsonPath)
	if os.IsNotExist(err) {
		return nil, WrapNotExistError(err)
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var f Finding
	err = json.Unmarshal(bytes, &f)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &f, nil
}
