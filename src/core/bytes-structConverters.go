package core

import (
	"bytes"
	"crypto"
	"encoding/binary"
	path2 "github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"log"
	"main.go/go-sphinxmixcrypto"
	"net"
	"time"
)

// Thoughts about routing bytes:
// SPHINX library used 16 bytes for routing, including a 1-byte prefix to indicate the type of the node
// My modified HORNET allows 8 bytes for routing information, out of which I use 4 for the ingress/egress ports
// I have not solved yet the issue where the requester and recursive resolver are perceived differently than a participating relay router
// i.e.: relay routers are addressed through the egress-ingress combination and represent their whole AS.
// But end nodes are probably not the only OR-participating node in the destination AS. So we need to address them separately, after reaching their AS through the egress-ingress combination
// Notably I could use 4 bytes to mock private subnet IPv4
// Solution 1: Use the 8 bytes as Prefix, 3xClient Address, 4xEgress-Ingress. Easiest for me, but requires ASes to have a dedicated addressing scheme for OR-participating nodes, limited to 2^24 addresses per AS
// Solution 2: Use the 8 bytes as 4xClient Address, 4xEgress-Ingress. ASes can use IPv4 private addressing. Limited to 2^32 per AS.
// Solution 2 is arguably the correct one, but requires me to dissociate routing info for sphinx from the data transmission phase.

// RoutingBytesToDataplanePath chooses Solution 2 of the comment above. R should be 8 bytes long.
func RoutingBytesToDataplanePath(R []byte) (snet.DataplanePath, net.IP) {
	// TODO use the ipv4 return where relevant!
	egress := binary.BigEndian.Uint16(R[0:2])
	nextIngress := binary.BigEndian.Uint16(R[2:4])

	return NewOneHopFull(egress, nextIngress), R[4:8]
}

// DataplanePathToBytes chooses Solution 2 of the comment above. ipv4 must have length 4 bytes. R will be 8 bytes long
func DataplanePathToBytes(pathReceived snet.DataplanePath, ipv4 net.IP) (R []byte) {
	oneHop := pathReceived.(path.OneHop)
	R = make([]byte, RoutingLength)

	binary.BigEndian.PutUint16(R[0:2], oneHop.FirstHop.ConsEgress)
	binary.BigEndian.PutUint16(R[2:4], oneHop.SecondHop.ConsIngress)

	if len(ipv4) != 4 {
		panic("ipv4 address must have length 4 bytes")
	}

	R = R[0:4]
	R = append(R, ipv4...)
	return R
}

// SphinxRoutingBytesToDataplanePath take a 16 bytes long R,
// prefixed by a byte corresponding to ExitNode, MoreHops or ClientHop (0, 255 or 128) followed by seven 0
func SphinxRoutingBytesToDataplanePath(R []byte) (snet.DataplanePath, net.IP, uint8) {
	// TODO use the ipv4 return where relevant!
	egress := binary.BigEndian.Uint16(R[8:10])
	nextIngress := binary.BigEndian.Uint16(R[10:12])

	if !bytes.Equal(make([]byte, 7), R[1:8]) {
		log.Println("R padding seems to be corrupted")
	}

	return NewOneHopFull(egress, nextIngress), R[12:16], R[0]
}

// sphinxRoutingBytesToDataplanePath outputs a 16 bytes long R,
// prefixed by a byte corresponding to nodetype ExitNode, MoreHops or ClientHop (0, 255 or 128) followed by seven 0
func DataplanePathToSphinxBytes(pathReceived snet.DataplanePath, ipv4 net.IP, nodetype uint8) (R []byte) {
	R = DataplanePathToBytes(pathReceived, ipv4)

	if nodetype != sphinxmixcrypto.ExitNode && nodetype != sphinxmixcrypto.MoreHops && nodetype != sphinxmixcrypto.ClientHop {
		panic("Wrong nodetype. Please read doc.")
	}

	prefix := make([]byte, 8)
	prefix[0] = nodetype
	return append(prefix, R...)
}

// NewOneHopFull calls scion NewOneHop but completes it with values of the next ingress interface id.
func NewOneHopFull(egress uint16, ingressNext uint16) path.OneHop {
	expiration := uint8(30)
	dpath, err := path.NewOneHop(egress, time.Now(), expiration, crypto.SHA256.New())
	if err != nil {
		log.Println(err)
	}
	dpath.SecondHop = path2.HopField{
		IngressRouterAlert: true,
		ConsIngress:        ingressNext,
		ExpTime:            expiration,
	}
	dpath.SecondHop.Mac = path2.MAC(crypto.SHA256.New(), dpath.Info, dpath.SecondHop, nil)
	return dpath
}

// BytesToSetupPacket unpacks a slice of bytes into a sphinx setup packet
func BytesToSetupPacket(rawSetupPacket []byte) SetupPacket {
	// TODO as the var name says, update as needed.
	ifAssigningFSPayloadLengthToSphinxPayloadLength := len(rawSetupPacket) - 2*FSPayloadLength
	setupPacket := SetupPacket{
		CHDR:          bytesToCHDR(rawSetupPacket[:CHDRLength]),
		SphinxHDR:     BytesToSphinxHeader(rawSetupPacket[CHDRLength:ifAssigningFSPayloadLengthToSphinxPayloadLength]),
		SphinxPayload: rawSetupPacket[ifAssigningFSPayloadLengthToSphinxPayloadLength : len(rawSetupPacket)-FSPayloadLength],
		FSPayload:     rawSetupPacket[len(rawSetupPacket)-FSPayloadLength:],
	}
	return setupPacket
}

// BytesToDataPacket unpacks a slice of bytes into an onion data packet
func BytesToDataPacket(rawDataPacket []byte) DataPacket {
	dataPacket := DataPacket{
		CHDR:        bytesToCHDR(rawDataPacket[:CHDRLength]),
		AHDR:        BytesToAHDR(rawDataPacket[CHDRLength : CHDRLength+AHDRLength]),
		DataPayload: rawDataPacket[CHDRLength+AHDRLength:],
	}
	return dataPacket
}

// bytesToCHDR unpacks a slice of bytes into a common header structure of both the set-up and data transmission phase
func bytesToCHDR(rawCHDR []byte) CHDR {
	CHDR := CHDR{
		Type:    rawCHDR[0],
		Hops:    rawCHDR[1],
		IVorEXP: rawCHDR[2:CHDRLength],
	}
	return CHDR
}

// BytesToAHDR unpacks a slice of bytes into an anonymous header structure used during the data transmission phase
func BytesToAHDR(rawAHDR []byte) AHDR {
	AHDR := AHDR{
		FS:      rawAHDR[:FSLength],
		Mac:     rawAHDR[FSLength : FSLength+SecurityParameter],
		Blinded: rawAHDR[FSLength+SecurityParameter:],
	}
	return AHDR
}

// SetupPacketToBytes packs a sphinx setup packet into a slice of bytes
func SetupPacketToBytes(setupPacket SetupPacket) []byte {
	byteSlice := make([]byte, 0)
	byteSlice = append(byteSlice, CHDRToBytes(setupPacket.CHDR)...)
	rawHeader := SphinxHeaderToBytes(setupPacket.SphinxHDR)
	byteSlice = append(byteSlice, rawHeader...)
	byteSlice = append(byteSlice, setupPacket.SphinxPayload...)
	byteSlice = append(byteSlice, setupPacket.FSPayload...)
	return byteSlice
}

// DataPacketToBytes packs an onion data packet into a slice of bytes
func DataPacketToBytes(dataPacket DataPacket) []byte {
	byteSlice := make([]byte, 0)
	byteSlice = append(byteSlice, CHDRToBytes(dataPacket.CHDR)...)
	byteSlice = append(byteSlice, AHDRToBytes(dataPacket.AHDR)...)
	byteSlice = append(byteSlice, dataPacket.DataPayload...)
	return byteSlice
}

// CHDRToBytes packs a common header structure of both the set-up and data transmission phase into a slice of bytes
func CHDRToBytes(CHDR CHDR) []byte {
	byteSlice := make([]byte, 0)
	byteSlice = append(byteSlice, CHDR.Type, CHDR.Hops)
	byteSlice = append(byteSlice, CHDR.IVorEXP...)
	return byteSlice
}

// AHDRToBytes packs an anonymous header structure used during the data transmission phase into a slice of bytes
func AHDRToBytes(AHDR AHDR) []byte {
	byteSlice := make([]byte, 0)
	byteSlice = append(byteSlice, AHDR.FS...)
	byteSlice = append(byteSlice, AHDR.Mac...)
	byteSlice = append(byteSlice, AHDR.Blinded...)
	return byteSlice
}

// BytesToFS unpacks a slice of bytes into an FS structure
func BytesToFS(rawDecryptedFS []byte) DecryptedFS {
	decryptedFS := DecryptedFS{
		Routing:   rawDecryptedFS[RoutingIndex:EXPIndex],
		EXP:       rawDecryptedFS[EXPIndex:SharedKeyIndex],
		SharedKey: rawDecryptedFS[SharedKeyIndex:],
	}
	return decryptedFS
}

// FSToBytes packs an FS structure into a slice of bytes
func FSToBytes(decryptedFS DecryptedFS) []byte {
	byteSlice := make([]byte, 0)
	byteSlice = append(byteSlice, decryptedFS.Routing...)
	byteSlice = append(byteSlice, decryptedFS.EXP...)
	byteSlice = append(byteSlice, decryptedFS.SharedKey...)
	return byteSlice
}

// DurationToEXPBytes converts a duration into a slice of bytes.
// EXPLength is 8 bytes, but to keep the size of the CHDR constant, must make it into 16 bytes
func DurationToEXPBytes(sessionDuration time.Duration) []byte {
	EXP := time.Now().Add(sessionDuration).Unix()
	EXPBytes := make([]byte, SecurityParameter)
	binary.BigEndian.PutUint64(EXPBytes, uint64(EXP))

	return EXPBytes
}

// BytesEXPToFSExpField converts from 16 to 8 bytes and works as tested in sphinx_test.go
func BytesEXPToFSExpField(EXP16bytes []byte) []byte {
	return EXP16bytes[:8]
}

// SphinxHeaderToBytes packs a sphinxMixHeader from the library into a slice of bytes
func SphinxHeaderToBytes(header *sphinxmixcrypto.MixHeader) []byte {
	rawHeader := make([]byte, 0)
	for _, b := range header.EphemeralKey {
		rawHeader = append(rawHeader, b)
	}
	rawHeader = append(rawHeader, header.RoutingInfo...)
	for _, b := range header.HeaderMAC {
		rawHeader = append(rawHeader, b)
	}

	return rawHeader
}

// BytesToSphinxHeader unpacks a slice of bytes into a sphinxMixHeader from the library
func BytesToSphinxHeader(rawHeader []byte) *sphinxmixcrypto.MixHeader {
	header := &sphinxmixcrypto.MixHeader{
		EphemeralKey: *(*[32]byte)(rawHeader[:32]),
		RoutingInfo:  rawHeader[32 : len(rawHeader)-16],
		HeaderMAC:    *(*[16]byte)(rawHeader[len(rawHeader)-16:]),
	}

	return header
}
