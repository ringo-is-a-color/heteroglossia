package proxy

import (
	"fmt"
	"net/url"
	"strconv"

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
	_, err := cmd.Run("gsettings", "set", "org.gnome.system.proxy", "mode", "manual")
	if err == nil {
		_, err = cmd.Run("gsettings", "set", "org.gnome.system.proxy.http", "host", host)
	}
	if err == nil {
		_, err = cmd.Run("gsettings", "set", "org.gnome.system.proxy.http", "port", portStr)
	}
	if authInfo.IsEmpty() {
		if err == nil {
			_, err = cmd.Run("gsettings", "set", "org.gnome.system.proxy.http", "use-authentication", "false")
		}
	} else {
		if err == nil {
			_, err = cmd.Run("gsettings", "set", "org.gnome.system.proxy.http", "authentication-user", authInfo.Username)
		}
		if err == nil {
			_, err = cmd.Run("gsettings", "set", "org.gnome.system.proxy.http", "authentication-password", authInfo.Password)
		}
		if err == nil {
			_, err = cmd.Run("gsettings", "set", "org.gnome.system.proxy.http", "use-authentication", "true")
		}
	}
	if err == nil {
		_, err = cmd.Run("gsettings", "set", "org.gnome.system.proxy.https", "host", host)
	}
	if err == nil {
		_, err = cmd.Run("gsettings", "set", "org.gnome.system.proxy.https", "port", portStr)
	}
	if err == nil {
		_, err = cmd.Run("gsettings", "set", "org.gnome.system.proxy.socks", "host", host)
	}
	if err == nil {
		_, err = cmd.Run("gsettings", "set", "org.gnome.system.proxy.socks", "port", portStr)
	}
	if err != nil {
		log.WarnWithError("fail to set system proxy for Gnome", err)
		err = nil
	}

	var kdeProxyHostWithPort string
	if authInfo.IsEmpty() {
		kdeProxyHostWithPort = fmt.Sprintf("%v %v", host, portStr)
	} else {
		kdeProxyHostWithPort = fmt.Sprintf("%v:%v@%v %v", url.QueryEscape(authInfo.Username), url.QueryEscape(authInfo.Password), host, strconv.Itoa(int(port)))
	}
	_, err = cmd.Run("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1")
	if err == nil {
		_, err = cmd.Run("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", "http://"+kdeProxyHostWithPort)
	}
	if err == nil {
		_, err = cmd.Run("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", "http://"+kdeProxyHostWithPort)
	}
	if err == nil {
		_, err = cmd.Run("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", "socks://"+kdeProxyHostWithPort)
	}
	if err != nil {
		log.WarnWithError("fail to set system proxy for KDE 5", err)
	}
	return nil
}

func disableSystemProxy() {
	_, err := cmd.Run("gsettings", "set", "org.gnome.system.proxy", "mode", "none")
	if err != nil {
		log.WarnWithError("fail to remove system proxy for Gnome", err)
		err = nil
	}

	_, err = cmd.Run("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0")
	if err != nil {
		log.WarnWithError("fail to remove system proxy for KDE 5", err)
		err = nil
	}
}
