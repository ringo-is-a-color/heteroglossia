package ss_carrier

import (
	"net"
	"strconv"

	pool "github.com/libp2p/go-buffer-pool"
	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

type serverInfo struct {
	hg           *conf.Hg
	preSharedKey []byte
	aeadOverhead int
}

func newServerInfo(hg *conf.Hg) *serverInfo {
	return &serverInfo{hg, hg.Password.Raw[:], gcmTagOverhead}
}

func ListenRequests(hg *conf.Hg, targetClient transport.Client) error {
	serverInfo := newServerInfo(hg)

	addr := ":" + strconv.Itoa(serverInfo.hg.TCPPort)
	return netutil.ListenTCPAndServe(nil, addr, func(conn net.Conn) {
		err := handleRequest(conn, serverInfo, targetClient)
		_ = conn.Close()
		if err != nil {
			log.InfoWithError("fail to handle a request over TCP", err)
		}
	})
}

func handleRequest(conn net.Conn, serverInfo *serverInfo, targetClient transport.Client) error {
	saltSize := len(serverInfo.preSharedKey)
	reqSaltWithFixedLenHeaderEncryptedSize := saltSize + reqFixedLenHeaderSize + serverInfo.aeadOverhead
	reqSaltWithFixedLenHeaderEncryptedBs := pool.Get(reqSaltWithFixedLenHeaderEncryptedSize)
	defer pool.Put(reqSaltWithFixedLenHeaderEncryptedBs)
	_, err := ioutil.ReadOnceExpectFull(conn, reqSaltWithFixedLenHeaderEncryptedBs)
	if err != nil {
		return err
	}

	repSubkey := deriveSubkey(serverInfo.preSharedKey, reqSaltWithFixedLenHeaderEncryptedBs[:saltSize])
	respAEAD, err := aeadCipher(repSubkey)
	if err != nil {
		return err
	}
	aeadRWC := new(aeadClientConn)
	aeadRWC.setAEADReader(respAEAD)

	reqFixedLenHeaderEncryptedBs := reqSaltWithFixedLenHeaderEncryptedBs[saltSize:]
	err = aeadRWC.decrypt(reqFixedLenHeaderEncryptedBs[:0], reqFixedLenHeaderEncryptedBs)
	if err != nil {
		return err
	}
	return nil
}
