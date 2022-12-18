package rule

import (
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
)

type (
	domainRulesByTagAndType map[string]map[string][]string
	ipSetByTag              map[string][][]byte
)

const (
	CborDomainRulesFilePath = "data/domain-rules.cbor"
	CborIpSetRulesFilePath  = "data/ip-set-rules.cbor"
)

var (
	domainRuleDataPool = sync.Pool{
		New: func() interface{} {
			domainRules := new(domainRulesByTagAndType)
			bs, err := ioutil.ReadFileFromExecutablePath(CborDomainRulesFilePath)
			if err != nil {
				log.Fatal("fail to load the domain rules' file", err)
			}

			err = decMode.Unmarshal(bs, domainRules)
			if err != nil {
				log.Fatal("fail to parse the domain rules' file", err)
			}
			return domainRules
		},
	}

	ipSetRulesDataPool = sync.Pool{
		New: func() interface{} {
			ipSetRules := new(ipSetByTag)
			bs, err := ioutil.ReadFileFromExecutablePath(CborIpSetRulesFilePath)
			if err != nil {
				log.Fatal("fail to load the IP set rules' file", err)
			}

			err = decMode.Unmarshal(bs, ipSetRules)
			if err != nil {
				log.Fatal("fail to parse the IP set rules' file", err)
			}
			return ipSetRules
		},
	}

	decMode cbor.DecMode
)

func init() {
	var err error
	decMode, err = cbor.DecOptions{
		MaxArrayElements: 1000000,
	}.DecMode()
	if err != nil {
		log.Fatal("fail to setup CBOR's 'DecOptions'", err)
	}
}
