package tls_carrier

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplaceCRLF(t *testing.T) {
	tests := []struct {
		arr      [16]byte
		expected [16]byte
	}{
		{[16]byte{1, 2, 3, 4}, [16]byte{1, 2, 3, 4}},
		{[16]byte{cr, lf, 3, 4}, [16]byte{cr, escapedLF, 3, 4}},
		{[16]byte{cr, lf, lf, 4}, [16]byte{cr, escapedLF, lf, 4}},
		{[16]byte{cr, lf, cr, 4}, [16]byte{cr, escapedLF, cr, 4}},
		{[16]byte{cr, lf, cr, lf}, [16]byte{cr, escapedLF, cr, escapedLF}},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, replaceCRLF(tt.arr), "no match", tt)
	}
}
