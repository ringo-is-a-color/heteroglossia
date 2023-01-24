package proxy

import (
	"regexp"
	"strconv"

	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/cmd"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/osutil"
)

func SetSystemProxy(host string, port uint16, authInfo *transport.HTTPSOCKSAuthInfo) error {
	serviceName, err := getCurrentNetworkServiceName()
	if err != nil {
		return err
	}
	osutil.RegisterProgramTerminationHandler(func() {
		err := disableSystemProxy()
		if err != nil {
			log.WarnWithError("fail to disable the macOS system proxy when shutdown", err)
		}
	})
	if authInfo != nil {
		_, err = cmd.Run("networksetup", "-setwebproxy", serviceName, host, strconv.Itoa(int(port)), "on", authInfo.Username, authInfo.Password)
		if err == nil {
			_, err = cmd.Run("networksetup", "-setsecurewebproxy", serviceName, host, strconv.Itoa(int(port)), "on", authInfo.Username, authInfo.Password)
		}
		if err == nil {
			_, err = cmd.Run("networksetup", "-setsocksfirewallproxy", serviceName, host, strconv.Itoa(int(port)), "on", authInfo.Username, authInfo.Password)
		}
	} else {
		// It seems the macOS 13 has a bug that it fails to turn off the auth from my testing
		_, err = cmd.Run("networksetup", "-setwebproxy", serviceName, host, strconv.Itoa(int(port)), "off")
		if err == nil {
			_, err = cmd.Run("networksetup", "-setsecurewebproxy", serviceName, host, strconv.Itoa(int(port)), "off")
		}
		if err == nil {
			_, err = cmd.Run("networksetup", "-setsocksfirewallproxy", serviceName, host, strconv.Itoa(int(port)), "off")
		}
	}
	return err
}

func disableSystemProxy() error {
	// always disable the current macOS network service's system proxy
	// instead of disabling the previous set one
	serviceName, err := getCurrentNetworkServiceName()
	if err != nil {
		return err
	}

	_, err = cmd.Run("networksetup", "-setwebproxystate", serviceName, "off")
	if err == nil {
		_, err = cmd.Run("networksetup", "-setsecurewebproxystate", serviceName, "off")
	}
	if err == nil {
		_, err = cmd.Run("networksetup", "-setsocksfirewallproxystate", serviceName, "off")
	}
	return err
}

func getCurrentNetworkServiceName() (string, error) {
	interfaceOutput, err := cmd.RunWithInput("/usr/sbin/scutil", "show State:/Network/Global/IPv4\n")
	if err != nil {
		return "", err
	}
	primaryServiceIDRegex := regexp.MustCompile("PrimaryService\\s*:\\s*(.+)")
	match := primaryServiceIDRegex.FindStringSubmatch(interfaceOutput)
	if len(match) <= 0 {
		return "", errors.New("fail to find the primary service")
	}
	primaryServiceID := match[1]

	serviceNameOutput, err := cmd.RunWithInput("/usr/sbin/scutil", "show Setup:/Network/Service/"+primaryServiceID+"\n")
	if err != nil {
		return "", err
	}
	serviceNameRegex := regexp.MustCompile("UserDefinedName\\s*:\\s*(.+)")
	match = serviceNameRegex.FindStringSubmatch(serviceNameOutput)
	if len(match) <= 0 {
		return "", errors.Newf("fail to find the primary service ID '%v''s corresponding service name", primaryServiceID)
	}
	return match[1], nil
}
