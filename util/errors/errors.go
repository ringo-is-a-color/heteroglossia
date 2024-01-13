package errors

import (
	"errors"
	"fmt"

	"github.com/mdobak/go-xerrors"
)

func New(msg string) error {
	return xerrors.New(msg)
}

func Newf(format string, a ...any) error {
	return xerrors.New(fmt.Sprintf(format, a...))
}

func WithStack(err error) error {
	return xerrors.New(err)
}

func Wrap(err error, msg string) error {
	return xerrors.New(err, msg)
}

func Wrapf(err error, format string, a ...any) error {
	return xerrors.New(err, fmt.Sprintf(format, a...))
}

var Join = xerrors.Append

var Is = errors.Is
