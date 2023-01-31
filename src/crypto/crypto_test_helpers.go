package crypto

import (
	"encoding/binary"
	"github.com/miekg/dns"
	"log"
	"main.go/core"
	"math/rand"
	"strings"
	"time"
)


// createDNSMessage is a duplicate of the real one for package reasons
func createDNSMessage(params core.DnsParameters) *dns.Msg {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     params.AA,
			AuthenticatedData: params.AD,
			CheckingDisabled:  params.CD,
			RecursionDesired:  params.RD,
			Opcode:            dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}
	if op, ok := dns.StringToOpcode[strings.ToUpper(params.Opcode)]; ok {
		m.Opcode = op
	}
	m.Rcode = dns.RcodeSuccess
	if rc, ok := dns.StringToRcode[strings.ToUpper(params.Rcode)]; ok {
		m.Rcode = rc
	}
	return m
}

// GenerateExampleDNSBytes is pseudo realistic DNS code. However, Onion usually also include the return header and the return IV
func GenerateExampleDNSBytes() []byte {
	qname := "www.example.org"
	qtype := dns.TypeA
	qclass := dns.ClassINET
	dnsParams := core.DefaultDNSParameters()
	m := createDNSMessage(dnsParams)
	m.Question[0] = dns.Question{Name: dns.Fqdn(qname), Qtype: qtype, Qclass: uint16(qclass)}
	m.Id = dns.Id()
	//fmt.Printf("%s", m.String())
	//fmt.Printf("\n;; size: %d bytes\n\n", m.Len())
	pureDNSpayload, err := m.Pack()
	if err != nil {
		log.Println(err)
		return nil
	}
	return pureDNSpayload
}

// GeneratePseudoRandomDNSBytes is pseudo realistic DNS code which includes some randomness in the domain name. However, Onion usually also include the return header and the return IV
func GeneratePseudoRandomDNSBytes() []byte {
	subLen := rand.Intn(20)
	sub := make([]byte, subLen)
	for i := 0; i < subLen; i++ {
		sub[i] = byte(65 + rand.Intn(25))
	}

	qname := "www.example.org/" + string(sub)
	qtype := dns.TypeA
	qclass := dns.ClassINET
	dnsParams := core.DefaultDNSParameters()
	m := createDNSMessage(dnsParams)
	m.Question[0] = dns.Question{Name: dns.Fqdn(qname), Qtype: qtype, Qclass: uint16(qclass)}
	m.Id = dns.Id()
	//fmt.Printf("%s", m.String())
	//fmt.Printf("\n;; size: %d bytes\n\n", m.Len())
	pureDNSpayload, err := m.Pack()
	if err != nil {
		log.Println(err)
		return nil
	}
	return pureDNSpayload
}

// GenerateExampleFSWithRandomRouting create a FS structure with garbage value for R, expiration time in 1 hour, and the given shared key.
func GenerateExampleFSWithRandomRouting(sharedKey []byte) []byte {
	// Random routing
	R := make([]byte, core.RoutingLength)
	_, _ = rand.Read(R)
	EXP := time.Now().Add(time.Hour).Unix()
	EXPBytes := make([]byte, core.EXPLength)
	binary.BigEndian.PutUint64(EXPBytes, uint64(EXP))

	return append(append(R, EXPBytes...), sharedKey...)
}
