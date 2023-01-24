package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"

	"github.com/ringo-is-a-color/heteroglossia/util/cli"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"golang.org/x/mod/semver"
)

const (
	hgBinaryLatestVersionURL        = "https://api.github.com/repos/ringo-is-a-color/heteroglossia/releases/latest"
	hgBinaryURLTemplate             = "https://github.com/ringo-is-a-color/heteroglossia/releases/download/%v/heteroglossia_%v_%v_%v.tar.gz"
	hgBinaryURLSHA256SumURLTemplate = "https://github.com/ringo-is-a-color/heteroglossia/releases/download/%v/sha256sums.txt"
)

func UpdateHgBinary(client *http.Client) (bool, string, error) {
	currentVersion := cli.GetVersionWithVPrefix()
	if !semver.IsValid(currentVersion) {
		return false, "", errors.New("the current binary has an invalid semantic version, so skip the update")
	}
	latestTagVersion, err := getLatestTagVersion(client)
	if err != nil {
		return false, "", err
	}
	if !semver.IsValid(latestTagVersion) {
		return false, "", errors.New("the latest version from GitHub is an invalid semantic version so skipping update")
	}

	if semver.Compare(latestTagVersion, currentVersion) > 0 {
		log.Info("start to update to the latest release version of heteroglossia", "version", latestTagVersion)
		executablePath, err := os.Executable()
		if err != nil {
			return false, "", errors.WithStack(err)
		}
		err = updateFile(client, executablePath, getHgBinaryURL(latestTagVersion), getHgBinaryURLSHA256SumURL(latestTagVersion))
		if err != nil {
			return false, "", err
		}
		return true, latestTagVersion, nil
	}
	return false, "", err
}

func getLatestTagVersion(client *http.Client) (string, error) {
	resp, err := client.Get(hgBinaryLatestVersionURL)
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", errors.Newf("bad status %v when checking the latest heteroglossia version", resp.Status)
	}

	decoder := json.NewDecoder(resp.Body)
	latest := new(Latest)
	err = decoder.Decode(latest)
	if err != nil {
		return "", errors.WithStack(err)
	}
	if latest.TagName == "" {
		return "", errors.New("fail to get the last tag name from GitHub")
	}
	return latest.TagName, nil
}

type Latest struct {
	TagName string `json:"tag_name"`
}

func getHgBinaryURL(version string) string {
	return fmt.Sprintf(hgBinaryURLTemplate, version, version[1:], runtime.GOOS, runtime.GOARCH)
}

func getHgBinaryURLSHA256SumURL(version string) string {
	return fmt.Sprintf(hgBinaryURLSHA256SumURLTemplate, version)
}
