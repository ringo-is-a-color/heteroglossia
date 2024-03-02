package rule

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"go4.org/netipx"
)

type Matcher struct {
	domainFullAndSuffixMatcher domainFullAndSuffixMatcher
	domainRegexMatcher         []regexp.Regexp
	ipCidrMatcher              *netipx.IPSet
	bakedMatchRules            []string
}

const (
	domainFullPrefix   = "domain-full/"
	domainSuffixPrefix = "domain-suffix/"
	domainRegexPrefix  = "domain-regex/"
	ipPrefix           = "ip/"
	cidrPrefix         = "cidr/"
	domainTagPrefix    = "domain-tag/"
	ipSetTagPrefix     = "ip-set-tag/"
)

func newMatcher(matchRules []string) *Matcher {
	return &Matcher{domainFullAndSuffixMatcher: newDomainFullAndSuffixMatcher(), bakedMatchRules: matchRules}
}

func (matcher *Matcher) CopyWithBakedRulesOnly() *Matcher {
	return newMatcher(matcher.bakedMatchRules)
}

func (matcher *Matcher) SetupRulesData(rulesQueryStore *DomainIPSetRulesQueryStore) error {
	var domainRegexMatcher []regexp.Regexp
	var ipSetBuilder netipx.IPSetBuilder

	for _, rule := range matcher.bakedMatchRules {
		switch {
		case strings.HasPrefix(rule, domainFullPrefix):
			domain := strings.TrimPrefix(rule, domainFullPrefix)
			matcher.domainFullAndSuffixMatcher.addDomainFullRule(domain)

		case strings.HasPrefix(rule, domainSuffixPrefix):
			domain := strings.TrimPrefix(rule, domainSuffixPrefix)
			matcher.domainFullAndSuffixMatcher.addDomainSuffixRule(domain)

		case strings.HasPrefix(rule, domainRegexPrefix):
			domainRegex := strings.TrimPrefix(rule, domainRegexPrefix)
			regex := regexp.MustCompile(domainRegex)
			domainRegexMatcher = append(domainRegexMatcher, *regex)

		case strings.HasPrefix(rule, ipPrefix):
			ip := strings.TrimPrefix(rule, ipPrefix)
			ipSetBuilder.Add(to6(netip.MustParseAddr(ip)))

		case strings.HasPrefix(rule, cidrPrefix):
			cidr := strings.TrimPrefix(rule, cidrPrefix)
			ipSetBuilder.AddPrefix(netip.MustParsePrefix(cidr))

		case strings.HasPrefix(rule, domainTagPrefix):
			domainTag := strings.TrimPrefix(rule, domainTagPrefix)
			err := rulesQueryStore.queryDomainRulesByTag(domainTag, func(domainType domainType, domain string) {
				switch domainType {
				case domainFull:
					matcher.domainFullAndSuffixMatcher.addDomainFullRule(domain)
				case domainSuffix:
					matcher.domainFullAndSuffixMatcher.addDomainSuffixRule(domain)
				case domainKeyword:
					regex := regexp.MustCompile("^.*" + regexp.QuoteMeta(domain) + ".*$")
					domainRegexMatcher = append(domainRegexMatcher, *regex)
				case domainRegex:
					regex := regexp.MustCompile(domain)
					domainRegexMatcher = append(domainRegexMatcher, *regex)
				}
			})
			if err != nil {
				return err
			}

		case strings.HasPrefix(rule, ipSetTagPrefix):
			ipSetTag := strings.TrimPrefix(rule, ipSetTagPrefix)
			err := rulesQueryStore.queryIpSetRulesByTag(ipSetTag, func(ip netip.Addr, bits int) {
				ipSetBuilder.AddPrefix(netip.PrefixFrom(to6(ip), bits))
			})
			if err != nil {
				return err
			}
		default:
			return errors.Newf("no matched rule item %v", rule)
		}
	}

	ipSet, err := ipSetBuilder.IPSet()
	if err != nil {
		return errors.New(err, "fail to build the IP set")
	}
	matcher.domainRegexMatcher = domainRegexMatcher
	matcher.ipCidrMatcher = ipSet
	return nil
}

func (matcher *Matcher) MatchDomain(domain string) bool {
	if matcher.domainFullAndSuffixMatcher.match(domain) {
		return true
	}
	for _, regex := range matcher.domainRegexMatcher {
		if regex.MatchString(domain) {
			return true
		}
	}
	return false
}

func (matcher *Matcher) MatchIP(ip *netip.Addr) bool {
	// we use IPv4-mapped IPv6s for IPv4s in our ip matcher
	ipv6 := to6(*ip)
	return matcher.ipCidrMatcher.Contains(ipv6)
}

func (matcher *Matcher) UnmarshalJSON(data []byte) error {
	var matchRules []string
	err := json.Unmarshal(data, &matchRules)
	if err != nil {
		return errors.New(err, "fail to parse 'match' rules")
	}

	createdMatcher := newMatcher(matchRules)
	*matcher = *createdMatcher
	return nil
}

// due to https://github.com/golang/go/issues/54365
func to6(addr netip.Addr) netip.Addr {
	if addr.Is4() {
		return netip.AddrFrom16(addr.As16())
	}
	return addr
}
