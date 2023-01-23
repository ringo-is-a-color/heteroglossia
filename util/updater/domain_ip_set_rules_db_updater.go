package updater

import (
	"net/http"
	"time"

	"github.com/ringo-is-a-color/heteroglossia/conf/rule"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
)

const (
	domainIPSetRulesFileURL          = "https://github.com/ringo-is-a-color/domain-ip-set-rules/raw/release/domain-ip-set-rules.db"
	domainIPSetRulesFileSHA256SumURL = "https://github.com/ringo-is-a-color/domain-ip-set-rules/raw/release/domain-ip-set-rules.db.sha256sum"

	rulesFileNeedUpdateInterval = 15 * 10 * time.Hour
)

func UpdateRulesFiles(client *http.Client) (bool, error) {
	update, err := needUpdateFile(rule.DomainIPSetRulesDBFilePathFromExecutable, rulesFileNeedUpdateInterval)
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
	return updateFile(client, rule.DomainIPSetRulesDBFilePathFromExecutable, domainIPSetRulesFileURL, domainIPSetRulesFileSHA256SumURL)
}
