package updater

import (
	"net/http"
	"time"

	"github.com/ringo-is-a-color/heteroglossia/conf/rule"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
)

const (
	domainRulesFileURL       = "https://cdn.jsdelivr.net/gh/ringo-is-a-color/domain-ip-set-rules@release/domain-rules.cbor"
	domainRulesFileSHA256URL = "https://cdn.jsdelivr.net/gh/ringo-is-a-color/domain-ip-set-rules@release/domain-rules.cbor.sha256sum"
	ipSetRulesFileURL        = "https://cdn.jsdelivr.net/gh/ringo-is-a-color/domain-ip-set-rules@release/ip-set-rules.cbor"
	ipSetRulesFileSHA256URL  = "https://cdn.jsdelivr.net/gh/ringo-is-a-color/domain-ip-set-rules@release/ip-set-rules.cbor.sha256sum"

	rulesFilesNeedUpdateInterval = 15 * 10 * time.Hour
)

func UpdateRulesFiles(client *http.Client) (bool, error) {
	update, err := needUpdateFile(rule.CborDomainRulesFilePath, rulesFilesNeedUpdateInterval)
	if err != nil {
		return false, err
	}
	if !update {
		return false, nil
	}

	err = updateRulesFiles(client)
	if err != nil {
		return false, err
	}
	return true, nil
}

func updateRulesFiles(client *http.Client) error {
	log.Info("start to update rules' files")
	err := updateFile(client, rule.CborDomainRulesFilePath, domainRulesFileURL, domainRulesFileSHA256URL)
	if err != nil {
		return err
	}
	return updateFile(client, rule.CborIpSetRulesFilePath, ipSetRulesFileURL, ipSetRulesFileSHA256URL)
}
