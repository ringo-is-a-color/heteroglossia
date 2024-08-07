package proxy

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/util/cmd"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
)

func SetSystemProxy(host string, port uint16, authInfo *conf.HTTPSOCKSAuthInfo) (unsetProxy func(), err error) {
	// https://developer-old.gnome.org/ProxyConfiguration/
	// org.gnome.system.proxy use-same-proxy and org.gnome.system.proxy.http enabled are not used so don't use them
	gnomeProxySetCommand := fmt.Sprintf(trimNewLinesForRawStringLiteral(`gsettings set org.gnome.system.proxy mode 'manual' && 
gsettings set org.gnome.system.proxy.http host '%[1]v' && 
gsettings set org.gnome.system.proxy.http port %[2]v && 
gsettings set org.gnome.system.proxy.http authentication-password '%[4]v' && 
gsettings set org.gnome.system.proxy.http authentication-user '%[5]v' && 
gsettings set org.gnome.system.proxy.http use-authentication %[3]v && 
gsettings set org.gnome.system.proxy.https host '%[1]v' && 
gsettings set org.gnome.system.proxy.https port %[2]v && 
gsettings set org.gnome.system.proxy.socks host '%[1]v' && 
gsettings set org.gnome.system.proxy.socks port %[2]v`),
		host, port, strconv.FormatBool(!authInfo.IsEmpty()), authInfo.Username, authInfo.Password)
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

	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	var kdeProxyHostWithPort string
	if authInfo.IsEmpty() {
		kdeProxyHostWithPort = fmt.Sprintf("%v:%v", host, port)
	} else {
		// there is a KDE bug that it fails to set a URL including both auth info and IPv6 address (e.g., http://username:password@[::1]:1080
		kdeProxyHostWithPort = fmt.Sprintf("%v:%v@%v:%v", url.QueryEscape(authInfo.Username), url.QueryEscape(authInfo.Password), host, port)
	}
	kdeProxySetCommand := fmt.Sprintf(trimNewLinesForRawStringLiteral(`kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key ProxyType 1 && 
kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key httpProxy '%v' && 
kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key httpsProxy '%v' && 
kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key socksProxy '%v'`),
		"http://"+kdeProxyHostWithPort, "http://"+kdeProxyHostWithPort, "socks://"+kdeProxyHostWithPort)
	_, err = cmd.Run("/bin/sh", "-c", kdeProxySetCommand)
	if err != nil {
		log.WarnWithError("fail to set system proxy for KDE 6", err)
	}
	return func() {
		unsetSystemProxy()
	}, nil
}

func unsetSystemProxy() {
	log.Info("try to unset the system proxy")
	gnomeProxyUnsetCommand := trimNewLinesForRawStringLiteral(`gsettings set org.gnome.system.proxy mode 'none' && 
gsettings set org.gnome.system.proxy.http host '8080' && 
gsettings set org.gnome.system.proxy.http port 0 && 
gsettings set org.gnome.system.proxy.http authentication-password '' && 
gsettings set org.gnome.system.proxy.http authentication-user '' && 
gsettings set org.gnome.system.proxy.http use-authentication false && 
gsettings set org.gnome.system.proxy.https host '' && 
gsettings set org.gnome.system.proxy.https port 0 && 
gsettings set org.gnome.system.proxy.socks host '' && 
gsettings set org.gnome.system.proxy.socks port 0`)
	_, stderr, err := cmd.RunWithStdoutErrResults("dbus-run-session", "--", "/bin/sh", "-c", gnomeProxyUnsetCommand)
	if err != nil {
		log.WarnWithError("fail to remove the system proxy for Gnome", err)
		err = nil
	}
	if stderr != "" {
		log.Info("standard error output (which might be expected) when running commands to unset the system proxy for Gnome", "stderr", stderr)
	}

	kdeProxyUnsetCommand := trimNewLinesForRawStringLiteral(`kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key ProxyType 0 && 
kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key httpProxy '' && 
kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key httpsProxy '' && 
kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key socksProxy ''`)
	_, err = cmd.Run("/bin/sh", "-c", kdeProxyUnsetCommand)
	if err != nil {
		log.WarnWithError("fail to remove the system proxy for KDE 6", err)
		err = nil
	}
}
