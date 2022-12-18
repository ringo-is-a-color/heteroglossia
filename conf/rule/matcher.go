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

func newMatcher(matchRules []string) (*Matcher, error) {
	matcher := new(Matcher)
	matcher.bakedMatchRules = matchRules
	matcher.domainFullAndSuffixMatcher = newDomainFullAndSuffixMatcher()
	var domainRegexMatcher []regexp.Regexp
	var ipSetBuilder netipx.IPSetBuilder

	for _, rule := range matchRules {
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
			domainRules := domainRuleDataPool.Get().(*domainRulesByTagAndType)
			domainsByType, ok := (*domainRules)[domainTag]
			domainRuleDataPool.Put(domainRules)
			if ok == false {
				return nil, errors.Newf("the domain tag '%v' doesn't exist", domainTag)
			}
			appendRegexesCount := 0
			domainKeywords, ok := domainsByType["keyword"]
			if ok {
				appendRegexesCount += len(domainKeywords)
			}
			domainRegexes, ok := domainsByType["regex"]
			if ok {
				appendRegexesCount += len(domainRegexes)
			}

			for k, rules := range domainsByType {
				switch k {
				case "full":
					for _, domainFull := range rules {
						matcher.domainFullAndSuffixMatcher.addDomainFullRule(domainFull)
					}
				case "suffix":
					for _, domainSuffix := range rules {
						matcher.domainFullAndSuffixMatcher.addDomainFullRule(domainSuffix)
					}
				case "keyword":
					for _, domainKeyword := range rules {
						regex := regexp.MustCompile(".*" + regexp.QuoteMeta(domainKeyword) + ".*")
						domainRegexMatcher = append(domainRegexMatcher, *regex)
					}
				case "regex":
					for _, domainRegex := range rules {
						regex := regexp.MustCompile(domainRegex)
						domainRegexMatcher = append(domainRegexMatcher, *regex)
					}
				}
			}

		case strings.HasPrefix(rule, ipSetTagPrefix):
			ipSetTag := strings.TrimPrefix(rule, ipSetTagPrefix)
			ipSetRules := ipSetRulesDataPool.Get().(*ipSetByTag)
			cidrs, ok := (*ipSetRules)[ipSetTag]
			ipSetRulesDataPool.Put(ipSetRules)
			if ok == false {
				return nil, errors.Newf("the IP set tag '%v' doesn't exist", ipSetTag)
			}
			for _, cidr := range cidrs {
				size := len(cidr)
				ip, ok := netip.AddrFromSlice(cidr[:size-1])
				if !ok {
					return nil, errors.Newf("invalid IP address length %v in the CIDR %s", size-1, cidr)
				}

				bits := int(cidr[size-1])
				if ip.Is4() {
					bits += 128 - 32
				}
				ipSetBuilder.AddPrefix(netip.PrefixFrom(to6(ip), bits))
			}
		default:
			return nil, errors.Newf("no matched rule item %v", rule)
		}
	}

	ipSet, err := ipSetBuilder.IPSet()
	if err != nil {
		return nil, errors.Wrap(err, "fail to build the IP set")
	}
	matcher.domainRegexMatcher = domainRegexMatcher
	matcher.ipCidrMatcher = ipSet
	return matcher, nil
}

func (matcher *Matcher) NewUpdatedMatcher() (*Matcher, error) {
	return newMatcher(matcher.bakedMatchRules)
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
		return errors.Wrap(err, "fail to parse 'match' rules")
	}

	createdMatcher, err := newMatcher(matchRules)
	if err != nil {
		return err
	}
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
