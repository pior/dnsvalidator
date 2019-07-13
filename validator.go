package dnsvalidator

import (
	"context"
	"errors"

	"github.com/domainr/dnsr"
	"github.com/miekg/dns"
)

type Validator struct {
	resolver *dnsr.Resolver
	client   *dns.Client
}

func New() *Validator {
	return &Validator{
		resolver: dnsr.New(0),
		client:   &dns.Client{},
	}
}

// Inspect queries all nameservers for a query name and type and return a report by nameserver.
func (v *Validator) Inspect(ctx context.Context, qname string, qtype string) (Report, error) {
	if !dns.IsFqdn(qname) {
		return nil, errors.New("qname is not FQDN")
	}

	namservers, err := v.FindNameservers(ctx, qname)
	if err != nil {
		return nil, err
	}

	report, err := v.QueryNameservers(ctx, qname, qtype, namservers)
	if err != nil {
		return nil, err
	}

	return report, nil
}

// FindNameservers tries to find the nameservers for a given query name, by iterating on parents.
// Returns the root nameservers if the domain does not exist.
func (v *Validator) FindNameservers(ctx context.Context, qname string) (nss []string, err error) {
	for ok := true; ok; qname, ok = parent(qname) {
		rrs, err := v.resolver.ResolveCtx(ctx, qname, "NS")
		if err != nil {
			return nil, err
		}

		for _, rr := range rrs {
			if rr.Type == "NS" {
				nss = append(nss, rr.Value)
			}
		}
		if len(nss) > 0 {
			return nss, nil
		}
	}

	return nil, errors.New("not found")
}

func (v *Validator) QueryNameservers(ctx context.Context, qname, qtype string, nameservers []string) (Report, error) {
	result := Report{}

	for _, nameserver := range nameservers {
		report, err := v.QueryNameserver(ctx, qname, qtype, nameserver)
		if err != nil {
			return nil, err
		}
		result = result.merge(report)
	}

	return result, nil
}

func (v *Validator) QueryNameserver(ctx context.Context, qname, qtype, nameserver string) (Report, error) {
	qname = dns.Fqdn(qname)

	// Find the nameserver IPs
	arrs, err := v.resolver.ResolveCtx(ctx, nameserver, "A")
	if err != nil {
		return nil, err
	}

	qmsg := buildQueryMSG(qname, qtype)
	report := Report{}

	// Accumulate the RRs from all nameservers
	for _, arr := range arrs {
		rmsg, _, err := v.client.ExchangeContext(ctx, qmsg, arr.Value+":53")
		if err != nil {
			return nil, err
		}

		rrs, err := buildRRs(rmsg.Answer, qname, qtype)
		if err != nil {
			return nil, err
		}

		report = report.with(nameserver, arr.Value, NSReport{rmsg.Rcode, rrs})
	}

	return report, nil
}

func buildQueryMSG(qname, qtype string) *dns.Msg {
	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}

	qmsg := &dns.Msg{}
	qmsg.SetQuestion(qname, dtype)
	qmsg.MsgHdr.RecursionDesired = false
	return qmsg
}
