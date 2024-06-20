package test

import (
	"github.com/ringo-is-a-color/heteroglossia/conf"
)

func ToProxyNode(hg *conf.Hg) *conf.ProxyNode {
	return &conf.ProxyNode{
		Host:        hg.Host,
		Password:    hg.Password,
		TCPPort:     hg.TCPPort,
		TLSPort:     hg.TLSPort,
		TLSCertFile: hg.TLSCertKeyPair.CertFile,
		QUICPort:    hg.QUICPort,
	}
}
