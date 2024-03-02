package rule

import (
	"database/sql"
	"net/netip"
	"os"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	_ "modernc.org/sqlite"
)

type domainType int

const (
	DomainIPSetRulesDBFilename = "domain-ip-set-rules.db"

	domainFull    = 0
	domainSuffix  = 1
	domainKeyword = 2
	domainRegex   = 3

	domainRulesSqlQueryTemplate = `
select type_id, value
from domains,
     json_each(domains.domains) domain
         join domain_tags ON domains.tag_id = domain_tags.id
where domain_tags.name = ?
`

	ipSetRulesSqlQueryTemplate = `
select type_id, cidrs
from ip_sets
         join ip_set_tags ON ip_sets.tag_id = ip_set_tags.id
where ip_set_tags.name = ?
`
)

type DomainIPSetRulesQueryStore struct {
	db *sql.DB
}

func NewDomainIPSetRulesQueryStore() (*DomainIPSetRulesQueryStore, error) {
	// sql.Open doesn't check file existence, so we check it manually
	_, err := os.Stat(DomainIPSetRulesDBFilename)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	db, err := sql.Open("sqlite", DomainIPSetRulesDBFilename)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &DomainIPSetRulesQueryStore{db}, nil
}

func (store *DomainIPSetRulesQueryStore) Close() {
	_ = store.db.Close()
}

func (store *DomainIPSetRulesQueryStore) queryDomainRulesByTag(tag string, consumer func(domainType domainType, domain string)) error {
	rows, err := store.db.Query(domainRulesSqlQueryTemplate, tag)
	if err != nil {
		return errors.WithStack(err)
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var atLeastOneRow = false
	var domainTypeID int
	var domain string
	for rows.Next() {
		atLeastOneRow = true
		err := rows.Scan(&domainTypeID, &domain)
		if err != nil {
			return errors.WithStack(err)
		}

		switch domainTypeID {
		case domainFull, domainSuffix, domainKeyword, domainRegex:
			consumer(domainType(domainTypeID), domain)
		default:
			return errors.Newf("invalid domain type %v when querying domain rules by tag 'domain-tag/%v'",
				domainTypeID, tag)
		}
	}

	if !atLeastOneRow {
		return errors.Newf("no domain found when querying domain rules by tag 'domain-tag/%v'", tag)
	}
	err = rows.Err()
	if err != nil {
		return err
	}
	return nil
}

func (store *DomainIPSetRulesQueryStore) queryIpSetRulesByTag(tag string, consumer func(ip netip.Addr, bits int)) error {
	rows, err := store.db.Query(ipSetRulesSqlQueryTemplate, tag)
	if err != nil {
		return errors.WithStack(err)
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var atLeastOneRow = false
	var cidrTypeID int
	var cidrs []byte
	for rows.Next() {
		atLeastOneRow = true
		err := rows.Scan(&cidrTypeID, &cidrs)
		if err != nil {
			return errors.WithStack(err)
		}

		switch cidrTypeID {
		case 0:
			return consumeCIDRsBytes(cidrs, true, tag, consumer)
		case 1:
			return consumeCIDRsBytes(cidrs, false, tag, consumer)
		default:
			return errors.Newf("invalid CIDR type %v when querying IP set rules by tag 'ip-set-tag/cn/%v'", cidrTypeID, tag)
		}
	}

	if !atLeastOneRow {
		return errors.Newf("no domain found when querying domain rules by tag 'ip-set-tag/cn/%v'", tag)
	}
	err = rows.Err()
	if err != nil {
		return err
	}
	return nil
}

func consumeCIDRsBytes(cidrsBytes []byte, ipv4 bool, tag string, consume func(ip netip.Addr, bits int)) error {
	var cidrSize int
	var ipNumber int
	if ipv4 {
		cidrSize = 5
		ipNumber = 4
	} else {
		cidrSize = 17
		ipNumber = 6
	}
	if len(cidrsBytes)%cidrSize != 0 {
		return errors.Newf("invalid IPv%v CIDR bytes length %v when querying IP set rules by tag %v",
			ipNumber, len(cidrsBytes), tag)
	}

	for i := 0; i < len(cidrsBytes); i += cidrSize {
		ip, ok := netip.AddrFromSlice(cidrsBytes[i : i+cidrSize-1])
		if !ok {
			return errors.Newf("invalid IP address length %v in the CIDR %v", cidrSize-1, cidrSize)
		}

		bits := int(cidrsBytes[i+cidrSize-1])
		if ipv4 {
			bits += 128 - 32
		}
		consume(ip, bits)
	}
	return nil
}
