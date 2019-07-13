package dnsvalidator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindNS(t *testing.T) {
	nss, err := New().FindNameservers(context.Background(), "cname.dnstest.pior.dev.")
	require.NoError(t, err)
	assert.True(t, len(nss) > 2 && len(nss) < 12)
}

func TestIntegration(t *testing.T) {
	dnsv := New()
	ctx := context.Background()

	report, err := dnsv.Inspect(ctx, "cname.dnstest.pior.dev.", "A")
	require.NoError(t, err)

	expectedNSs := []NS{
		NS{Name: "ns-cloud-e1.googledomains.com.", IP: "216.239.32.110"},
		NS{Name: "ns-cloud-e2.googledomains.com.", IP: "216.239.34.110"},
		NS{Name: "ns-cloud-e3.googledomains.com.", IP: "216.239.36.110"},
		NS{Name: "ns-cloud-e4.googledomains.com.", IP: "216.239.38.110"},
	}
	assert.ElementsMatch(t, expectedNSs, getAllNS(report))

	expectedRRs := []RR{
		{
			Name:  "cname.dnstest.pior.dev.",
			Type:  "CNAME",
			Value: "a.dnstest.pior.dev.",
			TTL:   300,
		},
		{
			Name:  "a.dnstest.pior.dev.",
			Type:  "A",
			Value: "1.2.3.4",
			TTL:   300,
		},
	}
	for _, nsreport := range report {
		assert.ElementsMatch(t, expectedRRs, nsreport.RRs)
	}

	err = report.Validate(expectedRRs)
	require.NoError(t, err)

	report, err = dnsv.Inspect(ctx, "cname.dnstest.pior.dev.", "CNAME")
	require.NoError(t, err)
	for _, nsreport := range report {
		assert.Equal(t, []RR{
			{
				Name:  "cname.dnstest.pior.dev.",
				Type:  "CNAME",
				Value: "a.dnstest.pior.dev.",
				TTL:   300,
			},
		}, nsreport.RRs)
	}

	err = report.Validate([]RR{
		{
			Name:  "cname.dnstest.pior.dev.",
			Type:  "CNAME",
			Value: "a.dnstest.pior.dev.",
		},
	})
	require.NoError(t, err)

	err = report.Validate([]RR{
		{
			Name:  "cname.dnstest.pior.dev.",
			Type:  "A",
			Value: "a.dnstest.pior.dev.",
		},
	})
	require.EqualError(t, err, `all nameservers failed the validation. detail:
- ns-cloud-e1.googledomains.com. (216.239.32.110): unexpected type (CNAME)
- ns-cloud-e2.googledomains.com. (216.239.34.110): unexpected type (CNAME)
- ns-cloud-e3.googledomains.com. (216.239.36.110): unexpected type (CNAME)
- ns-cloud-e4.googledomains.com. (216.239.38.110): unexpected type (CNAME)`)

	err = report.Validate([]RR{
		{
			Name:  "cname.dnstest.pior.dev.",
			Type:  "CNAME",
			Value: "new.dnstest.pior.dev.",
		},
	})
	require.EqualError(t, err, `all nameservers failed the validation. detail:
- ns-cloud-e1.googledomains.com. (216.239.32.110): unexpected data (a.dnstest.pior.dev.)
- ns-cloud-e2.googledomains.com. (216.239.34.110): unexpected data (a.dnstest.pior.dev.)
- ns-cloud-e3.googledomains.com. (216.239.36.110): unexpected data (a.dnstest.pior.dev.)
- ns-cloud-e4.googledomains.com. (216.239.38.110): unexpected data (a.dnstest.pior.dev.)`)

}

func TestIntegration_NX(t *testing.T) {
	dnsv := New()
	ctx := context.Background()

	report, err := dnsv.Inspect(ctx, "nx.dnstest.pior.dev.", "A")
	require.NoError(t, err)

	err = report.Validate([]RR{
		{
			Name:  "nx.dnstest.pior.dev.",
			Type:  "A",
			Value: "1.2.3.4",
		},
	})
	require.EqualError(t, err, `all nameservers failed the validation. detail:
- ns-cloud-e1.googledomains.com. (216.239.32.110): unsuccessful response code (NXDOMAIN)
- ns-cloud-e2.googledomains.com. (216.239.34.110): unsuccessful response code (NXDOMAIN)
- ns-cloud-e3.googledomains.com. (216.239.36.110): unsuccessful response code (NXDOMAIN)
- ns-cloud-e4.googledomains.com. (216.239.38.110): unsuccessful response code (NXDOMAIN)`)
}

func getAllNS(report Report) []NS {
	nss := []NS{}
	for ns := range report {
		nss = append(nss, ns)
	}
	return nss
}
