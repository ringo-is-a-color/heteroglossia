package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDomainFullMatch(t *testing.T) {
	tests := []struct {
		rule     string
		input    string
		expected bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "com", false},
		{"example.com", "www.example.com", false},
	}
	for _, tt := range tests {
		matcher := newDomainFullAndSuffixMatcher()
		matcher.addDomainFullRule(tt.rule)
		assert.Equal(t, tt.expected, matcher.match(tt.input), "no match", tt)
	}
}

func TestDomainSuffixMatch(t *testing.T) {
	tests := []struct {
		rule     string
		input    string
		expected bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", true},
		{"example.com", "com", false},
	}
	for _, tt := range tests {
		matcher := newDomainFullAndSuffixMatcher()
		matcher.addDomainSuffixRule(tt.rule)
		assert.Equal(t, tt.expected, matcher.match(tt.input), "no match", tt)
	}
}
