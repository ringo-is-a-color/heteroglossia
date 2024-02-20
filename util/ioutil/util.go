package ioutil

import (
	"io"
	"os"
	"path/filepath"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

// https://superuser.com/a/1652039
// Use a TCP MSS value because it may cover most common case

const TCPBufSize = 1448

// includes file's abs path when an error occurs

func ReadFile(filePath string) ([]byte, error) {
	fullPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}
	bs, err := os.ReadFile(fullPath)
	return bs, errors.WithStack(err)
}

func Read1(r io.Reader) (byte, error) {
	var bs [1]byte
	_, err := io.ReadFull(r, bs[:])
	return bs[0], errors.WithStack(err)
}

func ReadN(r io.Reader, n int) (int, []byte, error) {
	bs := make([]byte, n)
	count, err := io.ReadFull(r, bs)
	return count, bs, errors.WithStack(err)
}

func ReadOnceExpectFull(r io.Reader, buf []byte) (int, error) {
	count, err := r.Read(buf)
	if err == nil && count < len(buf) {
		return count, errors.Newf("expected %v byte(s) in one read call, but got %v", len(buf), count)
	}
	return count, errors.WithStack(err)
}

func ReadFull(r io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(r, buf)
	return n, errors.WithStack(err)
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
	if errors.Is(err, io.EOF) {
		return nil
	}
	return errors.WithStack(err)
}
