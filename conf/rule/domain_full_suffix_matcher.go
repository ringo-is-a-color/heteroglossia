package rule

import (
	"strings"
)

type domainFullAndSuffixMatcher map[string]*domainSegments

type domainSegments struct {
	match         match
	domainMatcher domainFullAndSuffixMatcher
}

type match byte

const (
	none   match = 0
	full   match = 1
	suffix match = 2
)

func newDomainFullAndSuffixMatcher() domainFullAndSuffixMatcher {
	return make(map[string]*domainSegments)
}

func (matcher domainFullAndSuffixMatcher) addDomainFullRule(domain string) {
	matcher.addDomainRule(domain, full)
}

func (matcher domainFullAndSuffixMatcher) addDomainSuffixRule(domain string) {
	matcher.addDomainRule(domain, suffix)
}

func (matcher domainFullAndSuffixMatcher) addDomainRule(domain string, matchType match) {
	segments := strings.Split(strings.ToLower(domain), ".")
	loopedDomainMatcher := matcher
	matchSuffix := false
	for i := len(segments) - 1; i >= 1; i-- {
		segment := segments[i]
		nextSegment, ok := loopedDomainMatcher[segment]
		if !ok {
			nextSegment = new(domainSegments)
			nextSegment.match = none
			nextSegment.domainMatcher = domainFullAndSuffixMatcher{}
			loopedDomainMatcher[segment] = nextSegment
		} else {
			if nextSegment.match == suffix {
				matchSuffix = true
				break
			}
		}

		if nextSegment.domainMatcher == nil {
			nextSegment.domainMatcher = domainFullAndSuffixMatcher{}
		}
		loopedDomainMatcher = nextSegment.domainMatcher
	}
	if matchSuffix {
		return
	}

	last := segments[0]
	nextSegment, ok := loopedDomainMatcher[last]
	if !ok {
		nextSegment = new(domainSegments)
		nextSegment.match = matchType
		loopedDomainMatcher[last] = nextSegment
	} else {
		if nextSegment.match != suffix {
			nextSegment.match = matchType
		}
	}
}

func (matcher domainFullAndSuffixMatcher) match(domain string) bool {
	segments := strings.Split(strings.ToLower(domain), ".")
	loopedDomainMatcher := matcher
	var loopedSegment *domainSegments
	for i := len(segments) - 1; i >= 0; i-- {
		segment := segments[i]
		nextSegment, ok := loopedDomainMatcher[segment]
		if !ok {
			return false
		}

		if nextSegment.match == suffix {
			return true
		}
		loopedDomainMatcher = nextSegment.domainMatcher
		loopedSegment = nextSegment
	}
	return loopedSegment.match == full
}
