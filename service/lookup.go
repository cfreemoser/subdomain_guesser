package service

import (
	"fmt"

	"github.com/miekg/dns"
)

type Result struct {
	IPAddress string
	Hostname  string
}

func Lookup(fqdn, serverAddr string) []Result {
	var result []Result
	var cfdn = traceCNAME(fqdn, serverAddr)

	ips, err := lookupARecord(cfdn, serverAddr)
	if err != nil {
		return result
	}

	for _, ip := range ips {
		result = append(result, Result{IPAddress: ip, Hostname: fqdn})
	}
	return result
}

func traceCNAME(fqdn, serverAddr string) string {
	cnames, err := lookupCNAMERecord(fqdn, serverAddr)
	if err != nil {
		return fqdn
	}

	if len(cnames) < 1 {
		return fqdn

	}

	return traceCNAME(cnames[0], serverAddr)
}

func lookupARecord(fqdn, serverAddr string) ([]string, error) {

	var msg dns.Msg
	var ips []string

	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	in, err := dns.Exchange(&msg, serverAddr)
	if err != nil {
		return ips, fmt.Errorf("dns exchanged failed: %w", err)
	}
	if len(in.Answer) < 1 {
		return ips, fmt.Errorf("no answer from dns")
	}

	for _, answer := range in.Answer {
		if a, ok := answer.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}

	return ips, nil
}

func lookupCNAMERecord(fqdn, serverAddr string) ([]string, error) {

	var msg dns.Msg
	var ips []string

	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)
	in, err := dns.Exchange(&msg, serverAddr)
	if err != nil {
		return ips, fmt.Errorf("dns exchanged failed: %w", err)
	}
	if len(in.Answer) < 1 {
		return ips, fmt.Errorf("no answer from dns")
	}

	for _, answer := range in.Answer {
		if a, ok := answer.(*dns.CNAME); ok {
			ips = append(ips, a.Target)
		}
	}

	return ips, nil
}
