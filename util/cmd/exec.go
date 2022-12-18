package cmd

import (
	"os/exec"
	"strings"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

func Run(name string, arg ...string) (string, error) {
	cmd, builder := exec.Command(name, arg...), new(strings.Builder)
	cmd.Stdout = builder
	err := cmd.Run()
	if err != nil {
		return "", errors.WithStack(err)
	}
	return builder.String(), nil
}

func RunWithInput(name string, input string) (string, error) {
	cmd, builder := exec.Command(name), new(strings.Builder)
	cmd.Stdout = builder
	cmd.Stdin = strings.NewReader(input)
	err := cmd.Run()
	if err != nil {
		return "", errors.WithStack(err)
	}
	return builder.String(), nil
}
