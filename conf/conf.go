package conf

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/ringo-is-a-color/heteroglossia/conf/rule"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

type Config struct {
	Inbounds struct {
		HTTPSOCKS *HTTPSOCKS `json:"http-socks"`
		Hg        *Hg        `json:"hg"`
	} `json:"inbounds"`
	Outbounds map[string]*ProxyNode `json:"outbounds" validate:"dive"`
	Route     Route                 `json:"route"`
	Misc      Misc                  `json:"misc"`
}

type HTTPSOCKS struct {
	Host        string `json:"host" validate:"ip|hostname_rfc1123"`
	Port        uint16 `json:"port" validate:"gte=0,lte=65536"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	SystemProxy bool   `json:"system-proxy"`
}

type Password struct {
	Raw    [16]byte
	String string
}

type Hg struct {
	Host                      string          `json:"host" validate:"ip|hostname_rfc1123"`
	Password                  Password        `json:"password" validate:"required"`
	TLSPort                   int             `json:"tls-port" validate:"gte=0,lte=65536"`
	TLSCertKeyPair            *TLSCertKeyPair `json:"tls-cert-key-pair"`
	TLSBadAuthFallbackSiteDir string          `json:"tls-bad-auth-fallback-site-dir"`
}

type ProxyNode struct {
	Host        string   `json:"host" validate:"ip|hostname_rfc1123"`
	Password    Password `json:"password" validate:"required"`
	TLSPort     int      `json:"tls-port" validate:"gte=0,lte=65536"`
	TLSCertFile string   `json:"tls-cert"`
}

type Route struct {
	Rules Rules  `json:"rules" validate:"dive"`
	Final string `json:"final" validate:"required"`
}

type Rules []Rule

type Rule struct {
	Matcher *rule.Matcher `json:"match"`
	Policy  string        `json:"policy" validate:"required"`
}

type Misc struct {
	HgBinaryAutoUpdate  bool `json:"hg-binary-auto-update"`
	RulesFileAutoUpdate bool `json:"rules-file-auto-update"`
	TLSKeyLog           bool `json:"tls-key-log"`
	VerboseLog          bool `json:"verbose-log"`
}

type TLSCertKeyPair struct {
	CertFile string
	KeyFile  string
}

func (rules *Rules) SetupRulesData() error {
	store, err := rule.NewDomainIPSetRulesQueryStore()
	if err != nil {
		return err
	}
	defer store.Close()

	for _, oldRule := range *rules {
		err := oldRule.Matcher.SetupRulesData(store)
		if err != nil {
			return err
		}
	}
	return nil
}

func (rules *Rules) CopyWithNewRulesData() (Rules, error) {
	newRules := make([]Rule, 0, len(*rules))
	for _, oldRule := range *rules {
		var newRule Rule
		matcher, err := oldRule.Matcher.CopyWithBakedRulesOnly()
		if err != nil {
			return nil, err
		}
		newRule.Matcher = matcher
		newRule.Policy = oldRule.Policy
		newRules = append(newRules, newRule)
	}
	return newRules, nil
}

const defaultTLSPort = 443

func (hg *Hg) UnmarshalJSON(data []byte) error {
	// https://stackoverflow.com/a/41102996
	type HgAlias Hg
	hgAlias := (*HgAlias)(hg)
	hgAlias.TLSPort = defaultTLSPort
	return json.Unmarshal(data, hgAlias)
}

func (node *ProxyNode) UnmarshalJSON(data []byte) error {
	type ProxyNodeAlias ProxyNode
	proxyNodeAlias := (*ProxyNodeAlias)(node)
	proxyNodeAlias.TLSPort = defaultTLSPort
	return json.Unmarshal(data, proxyNodeAlias)
}

func (pw *Password) UnmarshalJSON(data []byte) error {
	var pwStr string
	err := json.Unmarshal(data, &pwStr)
	if err != nil {
		return errors.Wrap(err, "fail to parse the 'password' field")
	}

	bs, err := hex.DecodeString(pwStr)
	if err != nil || len(bs) != 16 {
		return errors.New("the password should be 32 hex characters in length")
	}
	pw.Raw = [16]byte(bs)
	pw.String = pwStr
	return nil
}

func (pair *TLSCertKeyPair) UnmarshalJSON(data []byte) error {
	var certKeyStr string
	err := json.Unmarshal(data, &certKeyStr)
	if err != nil {
		return errors.Wrap(err, "fail to parse the 'tls-cert-key-pair' field")
	}

	certKeyPairs := strings.Split(certKeyStr, " ")
	if len(certKeyPairs) != 2 {
		return errors.New("the certificate and key file's paths must be separated by whitespace, e.g. 'tls-cert-key-pair = \"tls_cert.pem tls_key.pem\"'")
	}
	pair.CertFile = certKeyPairs[0]
	pair.KeyFile = certKeyPairs[1]
	return nil
}
