package cmd

import (
	"os/exec"
	"strings"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

func Run(name string, arg ...string) (string, error) {
	cmd, outputBuilder, errorBuilder := exec.Command(name, arg...), new(strings.Builder), new(strings.Builder)
	cmd.Stdout = outputBuilder
	cmd.Stderr = errorBuilder
	err := cmd.Run()
	if err != nil {
		return "", errors.Wrapf(err, "error '%v' when running command '%v %v'", errorBuilder.String(),
			name, strings.Join(arg, " "))
	}
	if errorBuilder.Len() > 0 {
		return "", errors.Newf("error '%v' when running command '%v %v'", errorBuilder.String(),
			name, strings.Join(arg, " "))
	}
	return outputBuilder.String(), nil
}

func RunWithStdoutErrResults(name string, arg ...string) (string, string, error) {
	cmd, outputBuilder, errorBuilder := exec.Command(name, arg...), new(strings.Builder), new(strings.Builder)
	cmd.Stdout = outputBuilder
	cmd.Stderr = errorBuilder
	err := cmd.Run()
	if err != nil {
		return "", "", errors.Wrapf(err, "error '%v' when running command '%v %v'", errorBuilder.String(),
			name, strings.Join(arg, " "))
	}
	return outputBuilder.String(), errorBuilder.String(), nil
}

func RunWithInput(name string, input string) (string, error) {
	cmd, outputBuilder, errorBuilder := exec.Command(name), new(strings.Builder), new(strings.Builder)
	cmd.Stdout = outputBuilder
	cmd.Stderr = errorBuilder
	cmd.Stdin = strings.NewReader(input)
	err := cmd.Run()
	if err != nil {
		return "", errors.Wrapf(err, "error '%v' when running command '%v' with '%v' input", errorBuilder.String(),
			name, input)
	}
	if errorBuilder.Len() > 0 {
		return "", errors.Newf("error '%v' when running command '%v' with '%v' input", errorBuilder.String(),
			name, input)
	}
	return outputBuilder.String(), nil
}
