package proxy

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/cmd"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/osutil"
)

func SetSystemProxy(host string, port uint16, authInfo *transport.HTTPSOCKSAuthInfo) error {
	osutil.RegisterProgramTerminationHandler(func() {
		disableSystemProxy()
	})
	portStr := strconv.Itoa(int(port))
	// https://developer-old.gnome.org/ProxyConfiguration/
	// org.gnome.system.proxy use-same-proxy and org.gnome.system.proxy.http enabled are not used so don't use them
	gnomeProxySetCommand := fmt.Sprintf(trimNewLine(`gsettings set org.gnome.system.proxy mode 'manual' && 
gsettings set org.gnome.system.proxy.http host '%[1]v' && 
gsettings set org.gnome.system.proxy.http port %[2]v && 
gsettings set org.gnome.system.proxy.http authentication-password '%[4]v' && 
gsettings set org.gnome.system.proxy.http authentication-user '%[5]v' && 
gsettings set org.gnome.system.proxy.http use-authentication %[3]v && 
gsettings set org.gnome.system.proxy.https host '%[1]v' && 
gsettings set org.gnome.system.proxy.https port %[2]v && 
gsettings set org.gnome.system.proxy.socks host '%[1]v' && 
gsettings set org.gnome.system.proxy.socks port %[2]v`),
		host, portStr, strconv.FormatBool(!authInfo.IsEmpty()), authInfo.Username, authInfo.Password)
	// use 'dbus-run-session' command to invoke the `gsettings` commands otherwise it won't work
	// due to https://askubuntu.com/q/276509
	_, stderr, err := cmd.RunWithStdoutErrResults("dbus-run-session", "--", "/bin/sh", "-c", gnomeProxySetCommand)
	if err != nil {
		log.WarnWithError("fail to set system proxy for Gnome", err)
		err = nil
	}
	if stderr != "" {
		log.Info("standard error output (which might be expected) when running commands to set system proxy for Gnome", "stderr", stderr)
	}

	var kdeProxyHostWithPort string
	if authInfo.IsEmpty() {
		kdeProxyHostWithPort = fmt.Sprintf("%v %v", host, portStr)
	} else {
		kdeProxyHostWithPort = fmt.Sprintf("%v:%v@%v %v", url.QueryEscape(authInfo.Username), url.QueryEscape(authInfo.Password), host, strconv.Itoa(int(port)))
	}
	kde5ProxySetupCommand := fmt.Sprintf(trimNewLine(`kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key ProxyType 1 && 
kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key httpProxy '%v' && 
kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key httpsProxy '%v' && 
kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key socksProxy '%v'`),
		"http://"+kdeProxyHostWithPort, "http://"+kdeProxyHostWithPort, "socks://"+kdeProxyHostWithPort)
	_, err = cmd.Run("/bin/sh", "-c", kde5ProxySetupCommand)
	if err != nil {
		log.WarnWithError("fail to set system proxy for KDE 5", err)
	}
	return nil
}

func disableSystemProxy() {
	gnomeProxyResetCommand := trimNewLine(`gsettings set org.gnome.system.proxy mode 'none' && 
gsettings set org.gnome.system.proxy.http host '8080' && 
gsettings set org.gnome.system.proxy.http port 0 && 
gsettings set org.gnome.system.proxy.http authentication-password '' && 
gsettings set org.gnome.system.proxy.http authentication-user '' && 
gsettings set org.gnome.system.proxy.http use-authentication false && 
gsettings set org.gnome.system.proxy.https host '' && 
gsettings set org.gnome.system.proxy.https port 0 && 
gsettings set org.gnome.system.proxy.socks host '' && 
gsettings set org.gnome.system.proxy.socks port 0`)
	_, stderr, err := cmd.RunWithStdoutErrResults("dbus-run-session", "--", "/bin/sh", "-c", gnomeProxyResetCommand)
	if err != nil {
		log.WarnWithError("fail to remove the system proxy for Gnome", err)
		err = nil
	}
	if stderr != "" {
		log.Info("standard error output (which might be expected) when running commands to reset the system proxy for Gnome", "stderr", stderr)
	}

	kde5ProxyResetCommand := trimNewLine(`kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key ProxyType 0 && 
kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key httpProxy '' && 
kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key httpsProxy '' && 
kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key socksProxy ''`)
	_, err = cmd.Run("/bin/sh", "-c", kde5ProxyResetCommand)
	if err != nil {
		log.WarnWithError("fail to remove the system proxy for KDE 5", err)
		err = nil
	}
}

func trimNewLine(s string) string {
	return strings.ReplaceAll(s, "\n", "")
}
