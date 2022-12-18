package ioutil

import (
	"io"
	"os"
	"path/filepath"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

// includes file's abs path when an error occurs

func ReadFile(filePath string) ([]byte, error) {
	fullPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}
	bs, err := os.ReadFile(fullPath)
	return bs, errors.WithStack(err)
}

func ReadFileFromExecutablePath(filePath string) ([]byte, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	path := filepath.Join(filepath.Dir(executablePath), filePath)
	return ReadFile(path)
}

func GetPathFromExecutablePath(filePath string) (string, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return "", errors.WithStack(err)
	}
	return filepath.Join(filepath.Dir(executablePath), filePath), nil
}

func Read1(r io.Reader) (byte, error) {
	var bs [1]byte
	_, err := io.ReadFull(r, bs[:])
	return bs[0], errors.WithStack(err)
}

func ReadN(r io.Reader, n int) ([]byte, error) {
	bs := make([]byte, n)
	_, err := io.ReadFull(r, bs)
	return bs, errors.WithStack(err)
}

func ReadByUint8(r io.Reader) ([]byte, error) {
	n, err := Read1(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	bs := make([]byte, n)
	_, err = io.ReadFull(r, bs)
	return bs, errors.WithStack(err)
}

func ReadStringByUint8(r io.Reader) (string, error) {
	bs, err := ReadByUint8(r)
	return string(bs), err
}

func Write_(w io.Writer, response []byte) error {
	_, err := w.Write(response)
	return errors.WithStack(err)
}

func Pipe(a, b io.ReadWriteCloser) error {
	done := make(chan error, 1)
	cp := func(r, w io.ReadWriteCloser) {
		_, err := io.Copy(r, w)
		done <- err
		_ = r.Close()
	}

	go cp(a, b)
	go cp(b, a)
	// only care about the first error as we close other directly when see first error
	err := <-done
	return errors.WithStack(err)
}
