package proxy

import (
	"strings"
)

func trimNewLinesForRawStringLiteral(s string) string {
	return strings.ReplaceAll(s, "\n", "")
}
