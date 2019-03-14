package cryptopals

import "testing"

func Test9(t *testing.T) {
	tcs := []struct {
		name    string
		input   string
		padding int
		output  string
	}{
		{
			name:    "none",
			input:   "123",
			padding: 3,
			output:  "123",
		},
		{
			name:    "one",
			input:   "123",
			padding: 4,
			output:  "123\x04",
		},
		{
			name:    "two",
			input:   "1234567",
			padding: 2,
			output:  "1234567\x04",
		},
		{
			name:    "Yellow sub",
			input:   "YELLOW SUBMARINE",
			padding: 20,
			output:  "YELLOW SUBMARINE\x04\x04\x04\x04",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			have := PKCSPadding([]byte(tc.input), tc.padding)
			expect := []byte(tc.output)
			equalBytes(t, have, expect)
		})
	}
}
