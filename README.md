# DNS Validator

[![GoDoc](https://godoc.org/github.com/pior/dnsvalidator?status.svg)](https://godoc.org/github.com/pior/dnsvalidator)

Validate that a set of resource records are set on all nameservers.

Uses [github.com/domainr/dnsr](https://github.com/domainr/dnsr) as recursor to avoid external DNS caching.

## Usage:
```go
import "github.com/pior/dnsvalidator"
```

```go
dnsv := dnsvalidator.New()
ctx := context.Background()

report, err := dnsv.Inspect(ctx, name, type)

expected := []RR{{Name:  "...", Type:  "CNAME", Value: "..."},}
err = report.Validate(expected)
```

See example: [cmd/test](cmd/test/main.go)

## License

The MIT License (MIT)
