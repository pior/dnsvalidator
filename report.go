package dnsvalidator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

type NS struct {
	Name string
	IP   string
}

type NSReport struct {
	Rcode int
	RRs   []RR
}

type Report map[NS]NSReport

func (r Report) merge(other Report) Report {
	for ns, report := range other {
		r[ns] = report
	}
	return r
}

func (r Report) with(name, ip string, report NSReport) Report {
	r[NS{name, ip}] = report
	return r
}

type errDetail struct {
	nameserver NS
	message    string
	detail     string
}

type ErrInvalid struct {
	message   string
	subErrors []errDetail
}

func (e *ErrInvalid) addError(nameserver NS, message, detail string) {
	e.subErrors = append(e.subErrors, errDetail{
		nameserver: nameserver,
		message:    message,
		detail:     detail,
	})
}

func (e *ErrInvalid) Error() string {
	details := []string{}
	for _, sub := range e.subErrors {
		detail := fmt.Sprintf("\n- %s (%s): %s", sub.nameserver.Name, sub.nameserver.IP, sub.message)
		if sub.detail != "" {
			detail += fmt.Sprintf(" (%s)", sub.detail)
		}
		details = append(details, detail)
	}

	if len(details) == 0 {
		return e.message
	}

	sort.Strings(details)
	return e.message + ". detail:" + strings.Join(details, "")
}

func (r *Report) Validate(expected []RR) error {
	if len(*r) == 0 {
		return &ErrInvalid{message: "nameservers not found"}
	}

	err := &ErrInvalid{}

	for ns, nsreport := range *r {
		if nsreport.Rcode != dns.RcodeSuccess {
			err.addError(ns, "unsuccessful response code", dns.RcodeToString[nsreport.Rcode])
			continue
		}

		for _, expectedRR := range expected {
			found, hasError := false, false
			for _, rr := range nsreport.RRs {
				if rr.Name != expectedRR.Name {
					continue
				}
				if rr.Type != expectedRR.Type {
					err.addError(ns, "unexpected type", rr.Type)
					hasError = true
					break
				}
				if rr.Value != expectedRR.Value {
					err.addError(ns, "unexpected data", rr.Value)
					hasError = true
					break
				}
				found = true
				break
			}
			if !found && !hasError {
				err.addError(ns, "records not found", "")
			}
		}
	}

	if len(err.subErrors) == 0 {
		return nil
	}
	if len(err.subErrors) == len(*r) {
		err.message = "all nameservers failed the validation"
	} else {
		err.message = "some nameservers failed the validation"
	}
	return err
}
