package stacktrace

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStackTrace(t *testing.T) {
	// Note: os.TempDir() doesn't create a directory, it only returns
	// the default directory for temporary files. Since we're not
	// creating or accessing any files in this test, the project dir
	// doesn't have to exist or be cleaned up, it just has to be a valid
	// absolute path on the current platform, which os.TempDir() is.
	projectDir := os.TempDir()
	parser := NewParser(projectDir)
	sourceFile := filepath.Join(projectDir, "api.cpp")

	var defaultStackTrace = []*StackFrame{{
		FrameNumber: 0,
		SourceFile:  "api.cpp",
		Function:    "DoStuff",
		Line:        24,
		Column:      10,
	}, {
		FrameNumber: 1,
		SourceFile:  "fuzz_targets/do_stuff_fuzzer.cpp",
		Function:    "LLVMFuzzerTestOneInput",
		Line:        11,
		Column:      3,
	}}

	tests := []struct {
		name               string
		logs               []string
		expectedStackTrace []*StackFrame
	}{
		{
			"stack_trace_with_no_valid_frame",
			[]string{
				"READ of size 4 at 0x603000001044 thread T0",
			},
			nil,
		},
		{
			"stack_trace_with_one_valid_frame",
			[]string{
				fmt.Sprintf("    #0 0x530ce7 in DoStuff(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) %s:24:10", sourceFile),
			},
			[]*StackFrame{{
				SourceFile:  "api.cpp",
				Function:    "DoStuff",
				FrameNumber: 0,
				Line:        24,
				Column:      10,
			}},
		},
		{
			"stack_trace_C++_function_names",
			[]string{
				fmt.Sprintf("    #0 0x530ce7 in test::Test::DoStuff(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) %s:24:10", sourceFile),
			},
			[]*StackFrame{{
				SourceFile:  "api.cpp",
				Function:    "test::Test::DoStuff",
				FrameNumber: 0,
				Line:        24,
				Column:      10,
			}},
		},
		{
			"stack_trace_with_one_valid_frame_and_header",
			[]string{
				"READ of size 4 at 0x603000001044 thread T0",
				fmt.Sprintf("    #0 0x530ce7 in DoStuff(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) %s:24:10", sourceFile),
			},
			[]*StackFrame{{
				FrameNumber: 0,
				SourceFile:  "api.cpp",
				Function:    "DoStuff",
				Line:        24,
				Column:      10,
			}},
		},
		{
			"inside_anonymous_namespace",
			[]string{
				"READ of size 4 at 0x603000001044 thread T0",
				fmt.Sprintf("	#0 0xd82574 in (anonymous namespace)::DoStuff(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) %s:24:10", sourceFile),
			},
			[]*StackFrame{{
				FrameNumber: 0,
				SourceFile:  "api.cpp",
				Function:    "(anonymous namespace)::DoStuff",
				Line:        24,
				Column:      10,
			}},
		},
		{
			"stack_trace_with_two_valid_frames",
			[]string{
				"READ of size 4 at 0x603000001044 thread T0",
				fmt.Sprintf("    #0 0x530ce7 in DoStuff(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) %s:24:10", sourceFile),
				fmt.Sprintf("    #1 0x52fde5 in LLVMFuzzerTestOneInput %s/fuzz_targets/do_stuff_fuzzer.cpp:11:3", projectDir),
			},
			defaultStackTrace,
		},
		{
			"two_frames_and_extra_logs",
			[]string{
				"READ of size 4 at 0x603000001044 thread T0",
				fmt.Sprintf("    #0 0x530ce7 in DoStuff(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) %s:24:10", sourceFile),
				fmt.Sprintf("    #1 0x52fde5 in LLVMFuzzerTestOneInput %s/fuzz_targets/do_stuff_fuzzer.cpp:11:3", projectDir),
				"0x603000001044 is located 0 bytes to the right of 20-byte region [0x603000001030,0x603000001044)",
				"allocated by thread T0 here:",
				"    #0 0x52c960 in operator new(unsigned long) /builds/code-intelligence/core/external/llvm/src/compiler-rt/lib/asan/asan_new_delete.cc:106:3",
			},
			defaultStackTrace,
		},
		{
			"stop_at_fuzz_target_entry",
			[]string{
				"READ of size 4 at 0x603000001044 thread T0",
				fmt.Sprintf("    #0 0x530ce7 in DoStuff(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) %s:24:10", sourceFile),
				"some logs between the two stack frames",
				fmt.Sprintf("    #1 0x52fde5 in LLVMFuzzerTestOneInput %s/fuzz_targets/do_stuff_fuzzer.cpp:11:3", projectDir),
				"    #2 0x54bf7b in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /builds/code-intelligence/core/external/llvm/src/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:576:17",
			},
			defaultStackTrace,
		},
		{
			"with_two_frames_and_logs_in_between",
			[]string{
				"READ of size 4 at 0x603000001044 thread T0",
				fmt.Sprintf("    #0 0x530ce7 in DoStuff(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) %s:24:10", sourceFile),
				"some logs between the two stack frames",
				fmt.Sprintf("    #1 0x52fde5 in LLVMFuzzerTestOneInput %s/fuzz_targets/do_stuff_fuzzer.cpp:11:3", projectDir),
			},
			defaultStackTrace,
		},
		{
			"stack_trace_without_column",
			[]string{
				fmt.Sprintf("    #0 0x530ce7 in DoStuff(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) %s:24", sourceFile),
			},
			[]*StackFrame{{
				SourceFile:  "api.cpp",
				Function:    "DoStuff",
				FrameNumber: 0,
				Line:        24,
			}},
		},
		{
			"log_with_undefined_behavior",
			[]string{
				fmt.Sprintf("%s:87:18: runtime error: load of value 3200171710, which is not a valid value for type 'YAML::Token::TYPE'", sourceFile),
				fmt.Sprintf("SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior %s/src/singledocparser.cpp:87:18 in", projectDir),
			},
			[]*StackFrame{{
				SourceFile: "api.cpp",
				Line:       87,
				Column:     18,
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trace, err := parser.Parse(tt.logs)
			require.NoError(t, err)
			require.Equal(t, tt.expectedStackTrace, trace)
		})
	}
}
