package main

import (
	"context"
	"fmt"

	"github.com/pior/dnsvalidator"
)

func main() {
	dnsv := dnsvalidator.New()
	ctx := context.Background()

	report, err := dnsv.Inspect(ctx, "cname.dnstest.pior.dev.", "CNAME")

	expected := []dnsvalidator.RR{
		{
			Name:  "cname.dnstest.pior.dev.",
			Type:  "CNAME",
			Value: "a.dnstest.pior.dev.",
		},
	}

	err = report.Validate(expected)
	if err == nil {
		fmt.Println("Valid!")
	} else {
		fmt.Println(err.Error())
	}
}
