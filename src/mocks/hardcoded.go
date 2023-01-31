package mocks

import (
	"crypto"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	path2 "github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"golang.org/x/crypto/curve25519"
	"log"
	"main.go/core"
	"main.go/go-sphinxmixcrypto"
	"time"
)

// GetHardcodedHopByHopPath provides a hardcoded back-and-forth SCION path hop information from the source node to the resolver through a single relay
// Addresses of the nodes should match what is given here for as long this pathing is used.
func GetHardcodedHopByHopPath() (forwardPath, backwardPath []snet.PacketInfo) {
	pathing := make([]snet.PacketInfo, 4)

	addrReq := snet.SCIONAddress{
		IA:   addr.MustIAFrom(1, 1),
		Host: addr.HostFromIPStr("11.11.11.11"),
	}
	addrRelay := snet.SCIONAddress{
		IA:   addr.MustIAFrom(1, 2),
		Host: addr.HostFromIPStr("22.22.22.22"),
	}
	addrResolver := snet.SCIONAddress{
		IA:   addr.MustIAFrom(1, 3),
		Host: addr.HostFromIPStr("33.33.33.33"),
	}

	dpath0 := core.NewOneHopFull(1, 21)
	dpath1 := core.NewOneHopFull(23, 3)
	dpath2 := core.NewOneHopFull(3, 23)
	dpath3 := core.NewOneHopFull(21, 1)

	pathing[0] = snet.PacketInfo{
		Destination: addrRelay,
		Source:      addrReq,
		Path:        dpath0,
	}
	pathing[1] = snet.PacketInfo{
		Destination: addrResolver,
		Source:      addrRelay,
		Path:        dpath1,
	}
	pathing[2] = snet.PacketInfo{
		Destination: addrRelay,
		Source:      addrResolver,
		Path:        dpath2,
	}
	pathing[3] = snet.PacketInfo{
		Destination: addrReq,
		Source:      addrRelay,
		Path:        dpath3,
	}
	return pathing[0:2], pathing[2:4]
}

// GetHardcodedHopByHopPath3_2Relay provides a hardcoded back-and-forth SCION path hop information from the source node to the resolver through 3 forward relay and 2 backward relay
// The topology is: Req->Rel2->Rel3->Rel4->Reso->Rel3->Rel2-Req
// Addresses of the nodes should match what is given here for as long this pathing is used.
func GetHardcodedHopByHopPath3_2Relay() (forwardPath, backwardPath []snet.PacketInfo) {
	forwardPath = make([]snet.PacketInfo, 4)
	backwardPath = make([]snet.PacketInfo, 3)

	addrReq := snet.SCIONAddress{
		IA:   addr.MustIAFrom(1, 1),
		Host: addr.HostFromIPStr("11.11.11.11"),
	}
	addrRelay2 := snet.SCIONAddress{
		IA:   addr.MustIAFrom(1, 2),
		Host: addr.HostFromIPStr("22.22.22.22"),
	}
	addrRelay3 := snet.SCIONAddress{
		IA:   addr.MustIAFrom(1, 3),
		Host: addr.HostFromIPStr("33.33.33.33"),
	}
	addrRelay4 := snet.SCIONAddress{
		IA:   addr.MustIAFrom(1, 4),
		Host: addr.HostFromIPStr("44.44.44.44"),
	}
	addrResolver := snet.SCIONAddress{
		IA:   addr.MustIAFrom(1, 5),
		Host: addr.HostFromIPStr("55.55.55.55"),
	}

	dpath0 := core.NewOneHopFull(12, 21)
	dpath1 := core.NewOneHopFull(23, 32)
	dpath2 := core.NewOneHopFull(34, 43)
	dpath3 := core.NewOneHopFull(45, 54)

	dpathb0 := core.NewOneHopFull(53, 35)
	dpathb1 := core.NewOneHopFull(32, 23)
	dpathb2 := core.NewOneHopFull(21, 12)

	forwardPath[0] = snet.PacketInfo{
		Destination: addrRelay2,
		Source:      addrReq,
		Path:        dpath0,
	}
	forwardPath[1] = snet.PacketInfo{
		Destination: addrRelay3,
		Source:      addrRelay2,
		Path:        dpath1,
	}
	forwardPath[2] = snet.PacketInfo{
		Destination: addrRelay4,
		Source:      addrRelay3,
		Path:        dpath2,
	}
	forwardPath[3] = snet.PacketInfo{
		Destination: addrResolver,
		Source:      addrRelay4,
		Path:        dpath3,
	}

	backwardPath[0] = snet.PacketInfo{
		Destination: addrRelay3,
		Source:      addrResolver,
		Path:        dpathb0,
	}
	backwardPath[1] = snet.PacketInfo{
		Destination: addrRelay2,
		Source:      addrRelay3,
		Path:        dpathb1,
	}
	backwardPath[2] = snet.PacketInfo{
		Destination: addrReq,
		Source:      addrRelay2,
		Path:        dpathb2,
	}
	return forwardPath, backwardPath
}

// CreatePacket is able to return a malformed packet, so error must be checked!
// It also uses the hardcoded pathing from getHardcodedHopByHopPath and hardcoded ports equal to 4x"AS-ID"
// As this is the non-onioned version, the pathing is E2E.
func CreatePacket(dnsPayload []byte, pathing []snet.PacketInfo) (snet.Packet, error) {
	var packet snet.Packet
	packet.Source = pathing[0].Source
	packet.Destination = pathing[len(pathing)-1].Destination
	decoded := scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrINF: 0,
				CurrHF:  0,
				SegLen:  [3]uint8{}, // TODO???
			},
			NumINF:  2,
			NumHops: 4,
		},
		InfoFields: []path2.InfoField{},
		HopFields:  []path2.HopField{},
	}

	for i := 0; i < 2; i++ {
		decoded.InfoFields = append(decoded.InfoFields, path2.InfoField{
			Peer:      false,
			ConsDir:   false,
			SegID:     uint16(i),
			Timestamp: util.TimeToSecs(time.Now()),
		})
	}
	for i := 0; i < 4; i++ {
		decoded.HopFields = append(decoded.HopFields, path2.HopField{
			IngressRouterAlert: false,
			EgressRouterAlert:  false,
			ExpTime:            30,
		})
		switch i {
		case 0:
			decoded.HopFields[i].ConsEgress = 1
		case 1:
			decoded.HopFields[i].ConsIngress = 21
		case 2:
			decoded.HopFields[i].ConsEgress = 23
		case 3:
			decoded.HopFields[i].ConsIngress = 3
		}
		decoded.HopFields[i].Mac = path2.MAC(crypto.SHA256.New(), decoded.InfoFields[i/2], decoded.HopFields[i], nil)
	}

	scionPath, err := path.NewSCIONFromDecoded(decoded)
	if err != nil {
		log.Println(err)
		return snet.Packet{}, err
	}

	packet.Path = scionPath
	udpPayload := snet.UDPPayload{
		SrcPort: 1111,
		DstPort: 3333,
		Payload: dnsPayload,
	}
	packet.Payload = udpPayload
	err = packet.Serialize()
	if err != nil {
		log.Println(err)
		return packet, err
	}
	return packet, nil
}

const requesterAsymPrivKey = "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"
const relayAsymPrivKey = "QRSTUVWXYZabcdefQRSTUVWXYZabcdef"
const relay2AsymPrivKey = "QRSTUVWXYZcbafedQRSTUVWXYZabcdef"
const relay3AsymPrivKey = "QRSTUVWXYZfedcbaQRSTUVWXYZabcdef"
const resolverAsymPrivKey = "ghijklmnopqrstuvghijklmnopqrstuv"

const HardcodedChachaEntropyKeyStr = "47ade5905376604cde0b57e732936b4298281c8a67b6a62c6107482eb69e2941"

func DefaultRequesterKeyStateHardcoded() *SimpleKeyState {
	privKey1 := []byte(requesterAsymPrivKey)
	pubKey1, err := curve25519.X25519(privKey1, curve25519.Basepoint)
	if err != nil {
		panic("Error while generating EC pubkey1")
	}
	requesterKeyState := &SimpleKeyState{
		PrivateKey: *(*[32]byte)(privKey1),
		PublicKey:  *(*[32]byte)(pubKey1),
		Id:         *(*[16]byte)([]byte("requester0123456")),
	}
	return requesterKeyState
}

// DefaultRelay1KeyStateHardcoded provides the keystate for the single relay of a single relay configuration or for relay 4 in a topology like: Req->Rel2->Rel3->Rel4->Reso->Rel3->Rel2-Req
func DefaultRelay1KeyStateHardcoded() *SimpleKeyState {
	privKey2 := []byte(relayAsymPrivKey)
	pubKey2, err := curve25519.X25519(privKey2, curve25519.Basepoint)
	if err != nil {
		panic("Error while generating EC pubkey2")
	}
	relayKeyState := &SimpleKeyState{
		PrivateKey: *(*[32]byte)(privKey2),
		PublicKey:  *(*[32]byte)(pubKey2),
		Id:         *(*[16]byte)([]byte("relay67890123456")),
	}
	return relayKeyState
}

func DefaultRelay2KeyStateHardcoded() *SimpleKeyState {
	privKey := []byte(relay2AsymPrivKey)
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		panic("Error while generating EC pubkey2")
	}
	relayKeyState := &SimpleKeyState{
		PrivateKey: *(*[32]byte)(privKey),
		PublicKey:  *(*[32]byte)(pubKey),
		Id:         *(*[16]byte)([]byte("relay27890123456")),
	}
	return relayKeyState
}

func DefaultRelay3KeyStateHardcoded() *SimpleKeyState {
	privKey := []byte(relay3AsymPrivKey)
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		panic("Error while generating EC pubkey2")
	}
	relayKeyState := &SimpleKeyState{
		PrivateKey: *(*[32]byte)(privKey),
		PublicKey:  *(*[32]byte)(pubKey),
		Id:         *(*[16]byte)([]byte("relay37890123456")),
	}
	return relayKeyState
}

func DefaultResolverKeyStateHardcoded() *SimpleKeyState {
	privKey3 := []byte(resolverAsymPrivKey)
	pubKey3, err := curve25519.X25519(privKey3, curve25519.Basepoint)
	if err != nil {
		panic("Error while generating resolver EC pubkey")
	}
	resolverKeyState := &SimpleKeyState{
		PrivateKey: *(*[32]byte)(privKey3),
		PublicKey:  *(*[32]byte)(pubKey3),
		Id:         *(*[16]byte)([]byte("resolver90123456")),
	}
	return resolverKeyState
}

// DefaultPKIHardcoded returns a static map of ID to keys compatible with sphinxmixcrypto package
// To be noted that they absolutely fail at security, as this function is intended to be used by all nodes in a mock set-up
// the private key are leaked.
// For now, the id nomenclature is 0 = requester, 1 = relay, 2 = resolver. Matching the pathing.
// For longer relay chains, it could be considered either that last = resolver, or 1 = resolver and 2+ are relays.
// For asymmetric pathing, ID are to be determined.
// In a real set-up, each node would set its private key, derive the public and only publish said public key in the map.
func DefaultPKIHardcoded() sphinxmixcrypto.SphinxPKI {

	pathingForward, pathingBackward := GetHardcodedHopByHopPath()
	nodeKeyStateMap := make(map[[16]byte]*SimpleKeyState)

	nodeKeyStateMap[*(*[16]byte)(core.DataplanePathToSphinxBytes(pathingForward[0].Path, []byte("forw"), uint8(sphinxmixcrypto.MoreHops)))] = DefaultRelay1KeyStateHardcoded()
	nodeKeyStateMap[*(*[16]byte)(core.DataplanePathToSphinxBytes(pathingForward[1].Path, []byte("forw"), uint8(sphinxmixcrypto.MoreHops)))] = DefaultResolverKeyStateHardcoded()
	nodeKeyStateMap[*(*[16]byte)(core.DataplanePathToSphinxBytes(pathingBackward[0].Path, []byte("back"), uint8(sphinxmixcrypto.MoreHops)))] = DefaultRelay1KeyStateHardcoded()
	nodeKeyStateMap[*(*[16]byte)(core.DataplanePathToSphinxBytes(pathingBackward[1].Path, []byte("back"), uint8(sphinxmixcrypto.MoreHops)))] = DefaultRequesterKeyStateHardcoded()

	return NewDummyPKI(nodeKeyStateMap)
}

// DefaultPKIHardcoded3_2 returns a static map of ID to keys compatible with sphinxmixcrypto package
// To be noted that they absolutely fail at security, as this function is intended to be used by all nodes in a mock set-up
// the private key are leaked.
// The topology is Req->Rel2->Rel3->Rel4->Reso->Rel3->Rel2-Req
// In a real set-up, each node would set its private key, derive the public and only publish said public key in the map.
func DefaultPKIHardcoded3_2() sphinxmixcrypto.SphinxPKI {

	pathingForward, pathingBackward := GetHardcodedHopByHopPath3_2Relay()
	nodeKeyStateMap := make(map[[16]byte]*SimpleKeyState)

	nodeKeyStateMap[*(*[16]byte)(core.DataplanePathToSphinxBytes(pathingForward[0].Path, []byte("forw"), uint8(sphinxmixcrypto.MoreHops)))] = DefaultRelay2KeyStateHardcoded()
	nodeKeyStateMap[*(*[16]byte)(core.DataplanePathToSphinxBytes(pathingForward[1].Path, []byte("forw"), uint8(sphinxmixcrypto.MoreHops)))] = DefaultRelay3KeyStateHardcoded()
	nodeKeyStateMap[*(*[16]byte)(core.DataplanePathToSphinxBytes(pathingForward[2].Path, []byte("forw"), uint8(sphinxmixcrypto.MoreHops)))] = DefaultRelay1KeyStateHardcoded()
	nodeKeyStateMap[*(*[16]byte)(core.DataplanePathToSphinxBytes(pathingForward[3].Path, []byte("forw"), uint8(sphinxmixcrypto.MoreHops)))] = DefaultResolverKeyStateHardcoded()
	nodeKeyStateMap[*(*[16]byte)(core.DataplanePathToSphinxBytes(pathingBackward[0].Path, []byte("back"), uint8(sphinxmixcrypto.MoreHops)))] = DefaultRelay3KeyStateHardcoded()
	nodeKeyStateMap[*(*[16]byte)(core.DataplanePathToSphinxBytes(pathingBackward[1].Path, []byte("back"), uint8(sphinxmixcrypto.MoreHops)))] = DefaultRelay2KeyStateHardcoded()
	nodeKeyStateMap[*(*[16]byte)(core.DataplanePathToSphinxBytes(pathingBackward[2].Path, []byte("back"), uint8(sphinxmixcrypto.MoreHops)))] = DefaultRequesterKeyStateHardcoded()

	return NewDummyPKI(nodeKeyStateMap)
}
