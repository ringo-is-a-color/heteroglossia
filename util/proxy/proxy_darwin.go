package proxy

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/cmd"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/osutil"
)

// not work when macOS's 'System Settings -> VPN' is enabled

func SetSystemProxy(host string, port uint16, authInfo *transport.HTTPSOCKSAuthInfo) error {
	serviceName, err := getCurrentNetworkServiceName()
	if err != nil {
		return err
	}
	osutil.RegisterProgramTerminationHandler(func() {
		err := unsetSystemProxy(serviceName, host, !authInfo.IsEmpty())
		if err != nil {
			log.WarnWithError("fail to disable the macOS system proxy when shutdown", err)
		}
	})
	var proxySetCommand string
	portStr := strconv.Itoa(int(port))
	if authInfo.IsEmpty() {
		proxySetCommand = fmt.Sprintf(trimNewLinesForRawStringLiteral(`networksetup -setwebproxy %[1]v %[2]v %[3]v off && 
networksetup -setsecurewebproxy %[1]v %[2]v %[3]v off && 
networksetup -setsocksfirewallproxy %[1]v %[2]v %[3]v off`),
			serviceName, host, portStr, authInfo.Username, authInfo.Password)
	} else {
		proxySetCommand = fmt.Sprintf(trimNewLinesForRawStringLiteral(`networksetup -setwebproxy %[1]v %[2]v %[3]v on %[4]v %[5]v && 
networksetup -setsecurewebproxy %[1]v %[2]v %[3]v on %[4]v %[5]v && 
networksetup -setsocksfirewallproxy %[1]v %[2]v %[3]v on %[4]v %[5]v`),
			serviceName, host, portStr, authInfo.Username, authInfo.Password)
	}
	_, err = cmd.Run("/bin/sh", "-c", proxySetCommand)
	return err
}

func unsetSystemProxy(serviceName, proxyHost string, hasAuthInfo bool) error {
	log.Info("try to unset the system proxy")
	proxyUnSetCommand := fmt.Sprintf(trimNewLinesForRawStringLiteral(`networksetup -setwebproxy %[1]v '' '' off && 
networksetup -setsecurewebproxy %[1]v '' '' off && 
networksetup -setsocksfirewallproxy %[1]v '' '' off &&
networksetup -setwebproxystate %[1]v off && 
networksetup -setsecurewebproxystate %[1]v off && 
networksetup -setsocksfirewallproxystate %[1]v off`),
		serviceName)
	_, err := cmd.Run("/bin/sh", "-c", proxyUnSetCommand)
	if hasAuthInfo {
		// see https://apple.stackexchange.com/a/351729
		// delete account info three times for HTTP/HTTPS/SOCKS proxy
		proxyAuthInfoUnSetCommand := fmt.Sprintf(trimNewLinesForRawStringLiteral(`security delete-internet-password -s %[1]v && 
security delete-internet-password -s %[1]v && 
security delete-internet-password -s %[1]v`),
			proxyHost)
		_, _ = cmd.Run("/bin/sh", "-c", proxyAuthInfoUnSetCommand)
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
