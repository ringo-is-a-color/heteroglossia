package updater

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/ringo-is-a-color/heteroglossia/util/cli"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
)

func needUpdateFile(filepath string, needUpdateInterval time.Duration) (bool, error) {
	ruleFileInfo, err := os.Stat(filepath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	interval := time.Now().Sub(ruleFileInfo.ModTime())
	return interval >= needUpdateInterval, nil
}

func updateFile(client *http.Client, filePath, fileURL, fileSHA256SumURL string) error {
	files := make([]*os.File, 0, 2)
	urls := []string{fileURL, fileSHA256SumURL}
	for _, url := range urls {
		file, err := downloadFile(client, url)
		if err != nil {
			return err
		}
		//goland:noinspection GoDeferInLoop
		defer func(file *os.File) {
			_ = file.Close()
		}(file)
		files = append(files, file)
	}

	for _, file := range files {
		_, err := file.Seek(0, io.SeekStart)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	filename := path.Base(fileURL)
	err := verifyRulesFileSHA256Sum(files[0], files[1], filename)
	if err != nil {
		return err
	}

	_, err = files[0].Seek(0, io.SeekStart)
	if err != nil {
		return errors.WithStack(err)
	}
	srcFile := files[0]
	if strings.HasSuffix(filename, ".tar.gz") {
		newDownloadHgBinaryPath, err := extractHgBinaryTarGz(files[0])
		if err != nil {
			return err
		}
		newDownloadHgBinaryFile, err := os.Open(newDownloadHgBinaryPath)
		if err != nil {
			return err
		}
		_ = os.Remove(files[0].Name())
		srcFile = newDownloadHgBinaryFile
	}

	// only remove SHA256Sum file finally, so we could check these files when an error occurs
	_ = os.Remove(files[1].Name())
	err = replaceFile(srcFile, filePath)
	if err != nil {
		return err
	}
	_ = os.Remove(srcFile.Name())
	return nil
}

func downloadFile(client *http.Client, url string) (*os.File, error) {
	filename := path.Base(url)
	file, err := os.CreateTemp("", filename)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Newf("bad status %v when downloading the %v file", resp.Status, filename)
	}

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return file, nil
}

func verifyRulesFileSHA256Sum(file *os.File, sha256SumFile *os.File, filename string) error {
	hash := sha256.New()
	_, err := io.Copy(hash, file)
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = io.Copy(hash, file)
	if err != nil {
		return errors.WithStack(err)
	}
	downloadFileSum := hex.EncodeToString(hash.Sum(nil))

	scanner := bufio.NewScanner(sha256SumFile)
	regexStr := fmt.Sprintf("^([^\\s]+)%v%v$", "\\s+", regexp.QuoteMeta(filename))
	regex := regexp.MustCompile(regexStr)
	expectedSum := ""
	for scanner.Scan() {
		match := regex.FindStringSubmatch(scanner.Text())
		if len(match) > 0 {
			expectedSum = match[1]
			break
		}
	}
	if expectedSum == "" {
		return errors.Newf("fail to find the SHA256 sum for the '%v' file", filename)
	}

	if downloadFileSum != expectedSum {
		return errors.Newf("the downloaded %v file's SHA256 is not the same as the one from the downloaded sha256sum file", file.Name())
	}
	return nil
}

func extractHgBinaryTarGz(tarGzFile *os.File) (string, error) {
	targetDir := filepath.Dir(tarGzFile.Name())
	gzipReader, err := gzip.NewReader(tarGzFile)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer func(gzipReader *gzip.Reader) {
		_ = gzipReader.Close()
	}(gzipReader)

	tarReader := tar.NewReader(gzipReader)
	var header *tar.Header
	newDownloadHgBinaryPath := ""
	for {
		header, err = tarReader.Next()
		if errors.IsIoEof(err) {
			if newDownloadHgBinaryPath == "" {
				return "", errors.Newf("fail to find the hg binary in the downloaded compressed file %v",
					tarGzFile.Name())
			}
			return newDownloadHgBinaryPath, nil
		}
		if err != nil {
			return "", errors.WithStack(err)
		}

		target := filepath.Join(targetDir, header.Name)
		switch header.Typeflag {
		case tar.TypeReg:
			uncompressedFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, os.FileMode(header.Mode))
			if err != nil {
				return "", errors.WithStack(err)
			}
			//goland:noinspection GoDeferInLoop
			defer func(file *os.File) {
				err := file.Close()
				if err != nil {
					log.WarnWithError("fail to close the file when extracting", err,
						"tar.gz file", tarGzFile.Name(), "uncompressed file name", header.Name)
				}
			}(uncompressedFile)

			_, err = io.Copy(uncompressedFile, tarReader)
			if err != nil {
				return "", errors.WithStack(err)
			}
			if strings.Contains(uncompressedFile.Name(), cli.AppName) {
				newDownloadHgBinaryPath = uncompressedFile.Name()
			}
		default:
			log.Warn("unknown type of the header when extracting",
				"tar.gz file", tarGzFile.Name(), "uncompressed file name", header.Name, "header type", header.Typeflag)
		}
	}
}

func replaceFile(src *os.File, dstFilepath string) error {
	err := os.MkdirAll(filepath.Dir(dstFilepath), 0755)
	if err != nil {
		return errors.WithStack(err)
	}

	dstNewFilepath, err := os.Create(dstFilepath + ".new")
	if err != nil {
		return errors.WithStack(err)
	}
	defer func(dstFile *os.File) {
		_ = dstFile.Close()
	}(dstNewFilepath)
	_, err = io.Copy(dstNewFilepath, src)
	if err != nil {
		return errors.WithStack(err)
	}
	srcFileStat, err := src.Stat()
	if err != nil {
		return errors.WithStack(err)
	}
	err = os.Chmod(dstNewFilepath.Name(), srcFileStat.Mode())
	if err != nil {
		return errors.WithStack(err)
	}

	if runtime.GOOS == "windows" {
		err = os.Rename(dstFilepath, dstFilepath+".old")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.WithStack(err)
		}
	}
	return errors.WithStack(os.Rename(dstFilepath+".new", dstFilepath))
}
