package core

import (
	"main.go/go-sphinxmixcrypto"
)

type DnsParameters struct {
	AA     bool
	AD     bool
	CD     bool
	RD     bool
	Opcode string
	Rcode  string
}

func DefaultDNSParameters() DnsParameters {
	return DnsParameters{
		AA:     false,
		AD:     false,
		CD:     false,
		RD:     true,
		Opcode: "query",
		Rcode:  "success",
	}
}

func DefaultSphinxParams() *sphinxmixcrypto.SphinxParams {
	return &sphinxmixcrypto.SphinxParams{
		PayloadSize: FSPayloadLength,
		MaxHops:     int(MaxPathLength),
	}
}

type SetupPacket struct {
	CHDR          CHDR
	SphinxHDR     SphinxHDR
	SphinxPayload SphinxPayload
	FSPayload     FSPayload
}

type SphinxHDR *sphinxmixcrypto.MixHeader
type SphinxPayload []byte
type FSPayload []byte

type DataPacket struct {
	CHDR        CHDR
	AHDR        AHDR
	DataPayload DataPayload
}

type CHDR struct {
	Type    byte
	Hops    byte
	IVorEXP []byte
}

type AHDR struct {
	FS      []byte
	Mac     []byte
	Blinded []byte
}

type DecryptedFS struct {
	Routing   []byte
	EXP       []byte
	SharedKey []byte
}

type DataPayload []byte
