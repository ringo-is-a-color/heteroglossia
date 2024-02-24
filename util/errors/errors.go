package errors

import (
	"errors"
	"fmt"

	"github.com/mdobak/go-xerrors"
)

// examples:
// New("access denied")
// New(ErrReadError, "access denied")

func New(vals ...any) error {
	return xerrors.New(vals)
}

// examples:
// Newf("access denied: %v", "404")
// Newf(ErrReadError, "access denied: %v", "404"))

func Newf(vals ...any) error {
	n := len(vals)
	if n > 0 {
		switch v := vals[0].(type) {
		case error:
			if n > 1 {
				format, ok := vals[1].(string)
				if ok {
					return xerrors.New(v, fmt.Sprintf(format, vals[2:]...))
				}
			}
		case string:
			return xerrors.New(fmt.Sprintf(v, vals[1:]...))
		}
	}

	panic(fmt.Sprintf("unsupported argument list: %v", vals))
}

func WithStack(err error) error {
	return xerrors.New(err)
}

var Join = xerrors.Append

var Is = errors.Is
