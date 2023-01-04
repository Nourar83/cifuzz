package sanitizer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/pkg/finding"
)

func TestParseAsFinding(t *testing.T) {
	type test struct {
		desc    string
		input   string
		error   finding.ErrorType
		details string
	}

	tests := []test{
		{desc: "LSAN fatal error", error: finding.ErrorType_CRASH, details: "", input: "==14237==LeakSanitizer has encountered a fatal error."},
		{desc: "LSAN memory leak", error: finding.ErrorType_CRASH, details: "detected memory leaks", input: "==7829==ERROR: LeakSanitizer: detected memory leaks"},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			f := ParseAsFinding(tc.input)
			require.NotNil(t, f)
			assert.Equal(t, tc.error, f.Type)
			assert.Equal(t, tc.input, f.Logs[0])
			assert.Equal(t, tc.details, f.Details)
		})
	}
}
