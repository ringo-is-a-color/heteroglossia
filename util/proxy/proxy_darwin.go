package proxy

import (
	"fmt"
	"regexp"

	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/cmd"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
)

// not work when macOS's 'System Settings -> VPN' is enabled

func SetSystemProxy(host string, port uint16, authInfo *transport.HTTPSOCKSAuthInfo) (unsetProxy func(), err error) {
	serviceName, err := currentNetworkServiceName()
	if err != nil {
		return nil, err
	}
	var proxySetCommand string
	if authInfo.IsEmpty() {
		proxySetCommand = fmt.Sprintf(trimNewLinesForRawStringLiteral(`networksetup -setwebproxy %[1]v %[2]v %[3]v off && 
networksetup -setsecurewebproxy %[1]v %[2]v %[3]v off && 
networksetup -setsocksfirewallproxy %[1]v %[2]v %[3]v off`),
			serviceName, host, port, authInfo.Username, authInfo.Password)
	} else {
		// try to unset the auth info for system proxy
		// may unset the auth info configured by user or other apps
		unsetAuthInfo(host)
		proxySetCommand = fmt.Sprintf(trimNewLinesForRawStringLiteral(`networksetup -setwebproxy %[1]v %[2]v %[3]v on %[4]v %[5]v && 
networksetup -setsecurewebproxy %[1]v %[2]v %[3]v on %[4]v %[5]v && 
networksetup -setsocksfirewallproxy %[1]v %[2]v %[3]v on %[4]v %[5]v`),
			serviceName, host, port, authInfo.Username, authInfo.Password)
	}
	_, err = cmd.Run("/bin/sh", "-c", proxySetCommand)
	if err != nil {
		log.WarnWithError("fail to set system proxy for macOS", err)
	}
	return func() {
		err := unsetSystemProxy(serviceName, host, !authInfo.IsEmpty())
		if err != nil {
			log.WarnWithError("fail to disable the macOS system proxy when shutdown", err)
		}
	}, err
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
		unsetAuthInfo(proxyHost)
	}
	return err
}

func unsetAuthInfo(proxyHost string) {
	// see https://apple.stackexchange.com/a/351729
	// delete the auth info three times for HTTP/HTTPS/SOCKS proxy
	proxyAuthInfoUnSetCommand := fmt.Sprintf(trimNewLinesForRawStringLiteral(`security delete-internet-password -s %[1]v && 
security delete-internet-password -s %[1]v && 
security delete-internet-password -s %[1]v`),
		proxyHost)
	_, _ = cmd.Run("/bin/sh", "-c", proxyAuthInfoUnSetCommand)
}

func currentNetworkServiceName() (string, error) {
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
