package ioutil

import (
	"io"
	"os"
	"path/filepath"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

const BufSize = 4096

// includes file's abs path when an error occurs

func ReadFile(filePath string) ([]byte, error) {
	fullPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}
	return errors.WithStack2(os.ReadFile(fullPath))
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

// it's better to check 'io.Eof' case when using this function

func ReadOnceExpectFull(r io.Reader, buf []byte) (int, error) {
	count, err := r.Read(buf)
	if err == nil && count < len(buf) {
		return count, errors.Newf("expect %v byte(s) in one read call, but got %v", len(buf), count)
	}
	if !errors.IsIoEof(err) {
		err = errors.WithStack(err)
	}
	return count, err
}

func ReadFull(r io.Reader, buf []byte) (int, error) {
	return errors.WithStack2(io.ReadFull(r, buf))
}

func ReadByUint8(r io.Reader) ([]byte, error) {
	b, err := Read1(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	bs := make([]byte, b)
	_, err = io.ReadFull(r, bs)
	return bs, errors.WithStack(err)
}

func ReadStringByUint8(r io.Reader) (string, error) {
	bs, err := ReadByUint8(r)
	return string(bs), err
}

func Write(w io.Writer, response []byte) (int, error) {
	return errors.WithStack2(w.Write(response))
}

func Write_(w io.Writer, response []byte) error {
	_, err := Write(w, response)
	return err
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
	// only care about the first error as we close other directly when see the first error
	err := <-done
	if errors.IsIoEof(err) {
		return nil
	}
	return errors.WithStack(err)
}
