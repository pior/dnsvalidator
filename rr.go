package dnsvalidator

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// RR represents a DNS resource record.
type RR struct {
	Name  string
	Type  string
	Value string
	TTL   int
}

// RRs represents a slice of DNS resource records.
// type RRs []RR

// String returns a string representation of an RR in zone-file format.
func (rr *RR) String() string {
	return rr.Name + "\t" + fmt.Sprintf("%10d", rr.TTL) + "\t" + rr.Type + "\t" + rr.Value
}

// convertRR converts a dns.RR to an RR.
// If the RR is not a type that this package uses,
// It will attempt to translate this if there are enough parameters
// Should all translation fail, it returns an undefined RR and false.
func convertRR(drr dns.RR) (RR, bool) {
	ttl := int(drr.Header().Ttl)
	switch t := drr.(type) {
	case *dns.SOA:
		return RR{toLowerFQDN(t.Hdr.Name), "SOA", toLowerFQDN(t.Ns), ttl}, true
	case *dns.NS:
		return RR{toLowerFQDN(t.Hdr.Name), "NS", toLowerFQDN(t.Ns), ttl}, true
	case *dns.CNAME:
		return RR{toLowerFQDN(t.Hdr.Name), "CNAME", toLowerFQDN(t.Target), ttl}, true
	case *dns.A:
		return RR{toLowerFQDN(t.Hdr.Name), "A", t.A.String(), ttl}, true
	case *dns.AAAA:
		return RR{toLowerFQDN(t.Hdr.Name), "AAAA", t.AAAA.String(), ttl}, true
	case *dns.TXT:
		return RR{toLowerFQDN(t.Hdr.Name), "TXT", strings.Join(t.Txt, "\t"), ttl}, true
	default:
		fields := strings.Fields(drr.String())
		if len(fields) >= 4 {
			return RR{toLowerFQDN(fields[0]), fields[3], strings.Join(fields[4:], "\t"), ttl}, true
		}
	}
	return RR{}, false
}

func buildRRs(drrs []dns.RR, qname, qtype string) (rrs []RR, err error) {
	for _, drr := range drrs {
		rr, ok := convertRR(drr)
		if !ok {
			return nil, errors.New("failed to convert RRs")
		}
		// if qtype != "CNAME" && rr.Type == "CNAME" {
		// 	continue // return CNAME only if this is the queried type
		// }
		rrs = append(rrs, rr)
	}
	return rrs, nil
}
