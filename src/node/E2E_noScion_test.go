package node

import (
	"bytes"
	"fmt"
	"github.com/scionproto/scion/pkg/snet"
	"log"
	"main.go/core"
	"main.go/crypto"
	"main.go/go-sphinxmixcrypto"
	"main.go/mocks"
	"testing"
	"time"
)

// TestE2E1Relay tests the full process with a single data transmission query with a topology: Req->Rel->Reso->Rel->Req
func TestE2E1Relay(t *testing.T) {
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// INIT NODES
	randReader, err := mocks.NewChachaEntropyReader(mocks.HardcodedChachaEntropyKeyStr)
	if err != nil {
		t.Fatalf("Can't get a ChachaEntropyReader")
	}
	requester := RequesterNode{
		node:                initNode(mocks.DefaultRequesterKeyStateHardcoded()),
		sessionDuration:     time.Duration(core.SessionDurationSeconds) * time.Second,
		session:             Session{},
		sphinxHeaderFactory: sphinxmixcrypto.NewMixHeaderFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded(), randReader),
		sphinxPacketFactory: sphinxmixcrypto.NewSphinxPacketFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded(), randReader),
	}
	pathingForward, pathingBackward := mocks.GetHardcodedHopByHopPath()
	requester.session.pathingForward = pathingForward
	requester.session.pathingBackward = pathingBackward
	err = requester.initSessionLocally()
	if err != nil {
		log.Println(err)
		t.Fatalf("requester couldn't init session locally")
	}
	relay := initNode(mocks.DefaultRelay1KeyStateHardcoded())
	resolver := initNode(mocks.DefaultResolverKeyStateHardcoded())

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// SPHINX
	requesterSphinxScionPacket, keyToInitiateForwardFSPayload, err := requester.setupSphinxSession_createScionPacket()
	if err != nil {
		t.Fatalf("requester couldn't create the scion packet")
	}

	relaySphinxScionPacket := &snet.Packet{}
	resolverSphinxScionAnswerPacket := &snet.Packet{}
	relaySphinxScionAnswerPacket := &snet.Packet{}

	chdrIn := requesterSphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR relay sphinx")
	}
	err = relay.relayProcessSphinxSetup(requesterSphinxScionPacket, relaySphinxScionPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[1].Path, []byte("forw")), core.DataplanePathToBytes(relaySphinxScionPacket.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct routing info")
	}

	chdrIn = relaySphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR resolver sphinx")
	}
	err = resolver.resolverProcessSphinxSetup(*relaySphinxScionPacket, resolverSphinxScionAnswerPacket)
	if err != nil {
		t.Fatalf("Resolver couldn't process the packet")
	}

	/*resolverRawSphinxAnswerPacket := resolverSphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload
	resolverSphinxAnswerPacket := bytesToSetupPacket(resolverRawSphinxAnswerPacket)
	_ = resolverSphinxAnswerPacket.SphinxPayload
	_ = resolverSphinxAnswerPacket.FSPayload*/

	/*
		This check makes sense, but requires a change in API just for the test.
		I did it when refactoring, but not willing to clutter my code just to facilitate one check.
		resolverRawSphinxAnswerPacket := resolverSphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload
		resolverSphinxAnswerPacket := bytesToSetupPacket(resolverRawSphinxAnswerPacket)

		if !bytes.Equal(sphinxHeaderToBytes(resolverSphinxAnswerPacket.SphinxHDR), sphinxHeaderToBytes(SHDRb)) {
			t.Fatalf("SHDRb are not equal")
		}
	*/

	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[0].Path, []byte("back")), core.DataplanePathToBytes(resolverSphinxScionAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Resolver's not getting the correct routing info")
	}

	chdrIn = resolverSphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR relay sphinx")
	}
	err = relay.relayProcessSphinxSetup(*resolverSphinxScionAnswerPacket, relaySphinxScionAnswerPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the backward packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[1].Path, []byte("back")), core.DataplanePathToBytes(relaySphinxScionAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Relay's not getting the correct backward routing info")
	}

	chdrIn = relaySphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR relay sphinx")
	}
	err = requester.setupSphinxSession_processAnswerAndGetFSes(*relaySphinxScionAnswerPacket, keyToInitiateForwardFSPayload)
	if err != nil {
		t.Fatalf("Requester couldn't process the answer")
	}

	// check correct FSes, but they are not exported by my API,
	// so I'll instead print them through the actual function addFStoPayload, which should not make it to prod.
	for i, FS := range requester.session.FSForward {
		log.Printf("%v: %v\n", i, FS)
	}
	for i, FS := range requester.session.FSBackward {
		log.Printf("%v: %v\n", i, FS)
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Requester should have a valid session now, send a DNS request
	// ONION ROUTING HORNET-LIKE

	originalDNSPayload := crypto.GenerateExampleDNSBytes()
	requesterORScionPacket, err := CreateOnion(originalDNSPayload, requester.session)
	if err != nil {
		log.Println(err)
		t.Fatalf("Onion creation unsuccessful")
	}

	initSizePayload := len(requesterORScionPacket.Payload.(snet.UDPPayload).Payload)

	chdrIn = requesterORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.DataTypeForward {
		t.Fatalf("Wrong CHDR relay OR")
	}

	relayORScionPacket := &snet.Packet{}
	resolverORScionAnswerPacket := &snet.Packet{}
	relayORScionAnswerPacket := &snet.Packet{}

	err = relay.relayProcessDataTypeForward(requesterORScionPacket, relayORScionPacket)
	if err != nil {
		log.Println(err)
		t.Fatalf("relay couldn't process the onion forward")
	}

	intermediateSizePayload := len(relayORScionPacket.Payload.(snet.UDPPayload).Payload)
	if initSizePayload != intermediateSizePayload {
		t.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, intermediateSizePayload)
	}

	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[1].Path, []byte("forw")), core.DataplanePathToBytes(relayORScionPacket.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct forward OR routing info")
	}

	chdrIn = relayORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.DataTypeForward {
		t.Fatalf("Wrong CHDR resolver OR")
	}

	finalPayload, R, sharedKey, err := resolver.removeLayer(relayORScionPacket.Payload.(snet.UDPPayload).Payload, true)
	if err != nil {
		t.Fatalf("Couldn't decrypt the packet at resolver, %v", err)
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[0].Path, []byte("back")), R) {
		t.Fatalf("Resolver's not getting the correct OR routing info")
	}

	decryptedPayload := finalPayload[core.CHDRLength:]

	//AHDRf := decryptedPayload[:core.AHDRLength] // This is garbage randomness, as there's no more FS/next routing
	AHDRb := decryptedPayload[core.AHDRLength : 2*core.AHDRLength]
	query := decryptedPayload[2*core.AHDRLength : len(decryptedPayload)-core.SecurityParameter]
	IV0b := decryptedPayload[len(decryptedPayload)-core.SecurityParameter:]

	if !bytes.Equal(originalDNSPayload, query) {
		fmt.Println(originalDNSPayload)
		fmt.Println(query)
		t.Fatalf("Onioning didn't work properly when decrypting query at resolver ")
	}

	originalDNSAnswer := []byte("success")

	// As per testHelpers.go prepareFakeSessionSymKeys comment, the symKey for the encryption as resolver == the symKey for the decryption
	O0b, err := crypto.ENC(sharedKey, IV0b, originalDNSAnswer, core.DataPaddingFactor, true)
	if err != nil {
		t.Fatalf("Couldn't encrypt the first layer of the onion back")
	}
	chdr := make([]byte, 0)
	chdr = append(chdr, core.DataTypeBackward, core.MaxPathLength)
	chdr = append(chdr, IV0b...)
	payloadBack := append(chdr, AHDRb...)
	payloadBack = append(payloadBack, O0b...)
	if !bytes.Contains(payloadBack, AHDRb) {
		t.Fatalf("Weird issue where AHDRb loses integrity")
	}

	initSizePayloadBackpath := len(payloadBack)

	udpPayload := snet.UDPPayload{
		SrcPort: 04104,
		DstPort: 04104,
		Payload: payloadBack,
	}
	resolverORScionAnswerPacket.Payload = udpPayload
	resolverORScionAnswerPacket.Path, _ = core.RoutingBytesToDataplanePath(R)


	chdrIn = resolverORScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.DataTypeBackward {
		t.Fatalf("Wrong CHDR relay OR backward")
	}

	// relay side
	err = relay.relayProcessDataTypeBackward(*resolverORScionAnswerPacket, relayORScionAnswerPacket)
	if err != nil {
		t.Fatalf("Couldn't process the packet at relay, %v", err)
	}

	relaySizePayloadBackpath := len(relayORScionAnswerPacket.Payload.(snet.UDPPayload).Payload)

	if initSizePayloadBackpath != relaySizePayloadBackpath {
		t.Fatalf("Payloads size not constant on the path back: %v vs %v", initSizePayloadBackpath, relaySizePayloadBackpath)
	}

	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[1].Path, []byte("back")), core.DataplanePathToBytes(relayORScionAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Relay's not getting the correct backward OR routing info")
	}

	chdrIn = relayORScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.DataTypeBackward {
		t.Fatalf("Wrong CHDR requester OR backward")
	}

	dnsAnswer, err := requester.onionDecrypt(relayORScionAnswerPacket.Payload.(snet.UDPPayload).Payload)
	if err != nil {
		t.Fatalf("Couldn't decrypt the onion at requester")
	}

	if !bytes.Equal(dnsAnswer, []byte("success")) {
		fmt.Println(dnsAnswer)
		fmt.Println([]byte("success"))
		t.Fatalf("Onioning didn't work properly when decrypting at requester")
	}

}

// TestE2E3_2Relay tests the full process with a single data transmission query with a topology: Req->Rel2->Rel3->Rel4->Reso->Rel3->Rel2->Req
func TestE2E3_2Relay(t *testing.T) {
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// INIT NODES
	randReader, err := mocks.NewChachaEntropyReader(mocks.HardcodedChachaEntropyKeyStr)
	if err != nil {
		t.Fatalf("Can't get a ChachaEntropyReader")
	}
	requester := RequesterNode{
		node:                initNode(mocks.DefaultRequesterKeyStateHardcoded()),
		sessionDuration:     time.Duration(core.SessionDurationSeconds) * time.Second,
		session:             Session{},
		sphinxHeaderFactory: sphinxmixcrypto.NewMixHeaderFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded3_2(), randReader),
		sphinxPacketFactory: sphinxmixcrypto.NewSphinxPacketFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded3_2(), randReader),
	}
	pathingForward, pathingBackward := mocks.GetHardcodedHopByHopPath3_2Relay()
	requester.session.pathingForward = pathingForward
	requester.session.pathingBackward = pathingBackward
	err = requester.initSessionLocally()
	if err != nil {
		log.Println(err)
		t.Fatalf("requester couldn't init session locally")
	}
	relay2 := initNode(mocks.DefaultRelay2KeyStateHardcoded())
	relay3 := initNode(mocks.DefaultRelay3KeyStateHardcoded())
	relay4 := initNode(mocks.DefaultRelay1KeyStateHardcoded())
	resolver := initNode(mocks.DefaultResolverKeyStateHardcoded())

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// SPHINX
	requesterSphinxScionPacket, keyToInitiateForwardFSPayload, err := requester.setupSphinxSession_createScionPacket()
	if err != nil {
		t.Fatalf("requester couldn't create the scion packet")
	}

	relay2SphinxScionPacket := &snet.Packet{}
	relay3SphinxScionPacket := &snet.Packet{}
	relay4SphinxScionPacket := &snet.Packet{}
	resolverSphinxScionAnswerPacket := &snet.Packet{}
	relay3SphinxScionAnswerPacket := &snet.Packet{}
	relay2SphinxScionAnswerPacket := &snet.Packet{}

	chdrIn := requesterSphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR relay sphinx")
	}
	err = relay2.relayProcessSphinxSetup(requesterSphinxScionPacket, relay2SphinxScionPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[1].Path, []byte("forw")), core.DataplanePathToBytes(relay2SphinxScionPacket.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct routing info")
	}

	chdrIn = relay2SphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR resolver sphinx")
	}
	err = relay3.relayProcessSphinxSetup(*relay2SphinxScionPacket, relay3SphinxScionPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[2].Path, []byte("forw")), core.DataplanePathToBytes(relay3SphinxScionPacket.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct routing info")
	}

	chdrIn = relay3SphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR resolver sphinx")
	}
	err = relay4.relayProcessSphinxSetup(*relay3SphinxScionPacket, relay4SphinxScionPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[3].Path, []byte("forw")), core.DataplanePathToBytes(relay4SphinxScionPacket.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct routing info")
	}

	chdrIn = relay4SphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR resolver sphinx")
	}
	err = resolver.resolverProcessSphinxSetup(*relay4SphinxScionPacket, resolverSphinxScionAnswerPacket)
	if err != nil {
		t.Fatalf("Resolver couldn't process the packet")
	}

	/*resolverRawSphinxAnswerPacket := resolverSphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload
	resolverSphinxAnswerPacket := bytesToSetupPacket(resolverRawSphinxAnswerPacket)
	_ = resolverSphinxAnswerPacket.SphinxPayload
	_ = resolverSphinxAnswerPacket.FSPayload*/

	/*
		This check makes sense, but requires a change in API just for the test.
		I did it when refactoring, but not willing to clutter my code just to facilitate one check.
		resolverRawSphinxAnswerPacket := resolverSphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload
		resolverSphinxAnswerPacket := bytesToSetupPacket(resolverRawSphinxAnswerPacket)

		if !bytes.Equal(sphinxHeaderToBytes(resolverSphinxAnswerPacket.SphinxHDR), sphinxHeaderToBytes(SHDRb)) {
			t.Fatalf("SHDRb are not equal")
		}
	*/

	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[0].Path, []byte("back")), core.DataplanePathToBytes(resolverSphinxScionAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Resolver's not getting the correct routing info")
	}

	chdrIn = resolverSphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR relay sphinx")
	}
	err = relay3.relayProcessSphinxSetup(*resolverSphinxScionAnswerPacket, relay3SphinxScionAnswerPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the backward packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[1].Path, []byte("back")), core.DataplanePathToBytes(relay3SphinxScionAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Relay's not getting the correct backward routing info")
	}

	chdrIn = relay3SphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR relay sphinx")
	}
	err = relay2.relayProcessSphinxSetup(*relay3SphinxScionAnswerPacket, relay2SphinxScionAnswerPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the backward packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[2].Path, []byte("back")), core.DataplanePathToBytes(relay2SphinxScionAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Relay's not getting the correct backward routing info")
	}

	chdrIn = relay2SphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR relay sphinx")
	}
	err = requester.setupSphinxSession_processAnswerAndGetFSes(*relay2SphinxScionAnswerPacket, keyToInitiateForwardFSPayload)
	if err != nil {
		t.Fatalf("Requester couldn't process the answer")
	}

	// check correct FSes, but they are not exported by my API,
	// so I'll instead print them through the actual function addFStoPayload, which should not make it to prod.
	for i, FS := range requester.session.FSForward {
		log.Printf("%v: %v\n", i, FS)
	}
	for i, FS := range requester.session.FSBackward {
		log.Printf("%v: %v\n", i, FS)
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Requester should have a valid session now, send a DNS request
	// ONION ROUTING HORNET-LIKE

	originalDNSPayload := crypto.GenerateExampleDNSBytes()
	requesterORScionPacket, err := CreateOnion(originalDNSPayload, requester.session)
	if err != nil {
		log.Println(err)
		t.Fatalf("Onion creation unsuccessful")
	}

	initSizePayload := len(requesterORScionPacket.Payload.(snet.UDPPayload).Payload)

	chdrIn = requesterORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.DataTypeForward {
		t.Fatalf("Wrong CHDR relay OR")
	}

	relay2ORScionPacket := &snet.Packet{}
	relay3ORScionPacket := &snet.Packet{}
	relay4ORScionPacket := &snet.Packet{}
	resolverORScionAnswerPacket := &snet.Packet{}
	relay3ORScionAnswerPacket := &snet.Packet{}
	relay2ORScionAnswerPacket := &snet.Packet{}

	err = relay2.relayProcessDataTypeForward(requesterORScionPacket, relay2ORScionPacket)
	if err != nil {
		log.Println(err)
		t.Fatalf("relay2 couldn't process the onion forward")
	}
	intermediateSizePayload := len(relay2ORScionPacket.Payload.(snet.UDPPayload).Payload)
	if initSizePayload != intermediateSizePayload {
		t.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, intermediateSizePayload)
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[1].Path, []byte("forw")), core.DataplanePathToBytes(relay2ORScionPacket.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct forward OR routing info")
	}

	chdrIn = relay2ORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.DataTypeForward {
		t.Fatalf("Wrong CHDR resolver OR")
	}
	err = relay3.relayProcessDataTypeForward(*relay2ORScionPacket, relay3ORScionPacket)
	if err != nil {
		log.Println(err)
		t.Fatalf("relay3 couldn't process the onion forward")
	}
	intermediateSizePayload = len(relay3ORScionPacket.Payload.(snet.UDPPayload).Payload)
	if initSizePayload != intermediateSizePayload {
		t.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, intermediateSizePayload)
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[2].Path, []byte("forw")), core.DataplanePathToBytes(relay3ORScionPacket.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct forward OR routing info")
	}

	chdrIn = relay3ORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.DataTypeForward {
		t.Fatalf("Wrong CHDR resolver OR")
	}
	err = relay4.relayProcessDataTypeForward(*relay3ORScionPacket, relay4ORScionPacket)
	if err != nil {
		log.Println(err)
		t.Fatalf("relay4 couldn't process tWhe onion forward")
	}
	intermediateSizePayload = len(relay4ORScionPacket.Payload.(snet.UDPPayload).Payload)
	if initSizePayload != intermediateSizePayload {
		t.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, intermediateSizePayload)
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[3].Path, []byte("forw")), core.DataplanePathToBytes(relay4ORScionPacket.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct forward OR routing info")
	}

	chdrIn = relay4ORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.DataTypeForward {
		t.Fatalf("Wrong CHDR resolver OR")
	}

	finalPayload, R, sharedKey, err := resolver.removeLayer(relay4ORScionPacket.Payload.(snet.UDPPayload).Payload, true)
	if err != nil {
		t.Fatalf("Couldn't decrypt the packet at resolver, %v", err)
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[0].Path, []byte("back")), R) {
		t.Fatalf("Resolver's not getting the correct OR routing info")
	}

	decryptedPayload := finalPayload[core.CHDRLength:]

	//AHDRf := decryptedPayload[:core.AHDRLength] // This is garbage randomness, as there's no more FS/next routing
	AHDRb := decryptedPayload[core.AHDRLength : 2*core.AHDRLength]
	query := decryptedPayload[2*core.AHDRLength : len(decryptedPayload)-core.SecurityParameter]
	IV0b := decryptedPayload[len(decryptedPayload)-core.SecurityParameter:]

	if !bytes.Equal(originalDNSPayload, query) {
		fmt.Println(originalDNSPayload)
		fmt.Println(query)
		t.Fatalf("Onioning didn't work properly when decrypting query at resolver ")
	}

	originalDNSAnswer := []byte("success")

	// As per testHelpers.go prepareFakeSessionSymKeys comment, the symKey for the encryption as resolver == the symKey for the decryption
	O0b, err := crypto.ENC(sharedKey, IV0b, originalDNSAnswer, core.DataPaddingFactor, true)
	if err != nil {
		t.Fatalf("Couldn't encrypt the first layer of the onion back")
	}
	chdr := make([]byte, 0)
	chdr = append(chdr, core.DataTypeBackward, core.MaxPathLength)
	chdr = append(chdr, IV0b...)
	payloadBack := append(chdr, AHDRb...)
	payloadBack = append(payloadBack, O0b...)
	if !bytes.Contains(payloadBack, AHDRb) {
		t.Fatalf("Weird issue where AHDRb loses integrity")
	}

	initSizePayloadBackpath := len(payloadBack)

	udpPayload := snet.UDPPayload{
		SrcPort: 04104,
		DstPort: 04104,
		Payload: payloadBack,
	}
	resolverORScionAnswerPacket.Payload = udpPayload
	resolverORScionAnswerPacket.Path, _ = core.RoutingBytesToDataplanePath(R)

	chdrIn = resolverORScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.DataTypeBackward {
		t.Fatalf("Wrong CHDR relay OR backward")
	}

	// relay side
	err = relay3.relayProcessDataTypeBackward(*resolverORScionAnswerPacket, relay3ORScionAnswerPacket)
	if err != nil {
		t.Fatalf("Couldn't process the packet at relay, %v", err)
	}
	relaySizePayloadBackpath := len(relay3ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload)
	if initSizePayloadBackpath != relaySizePayloadBackpath {
		t.Fatalf("Payloads size not constant on the path back: %v vs %v", initSizePayloadBackpath, relaySizePayloadBackpath)
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[1].Path, []byte("back")), core.DataplanePathToBytes(relay3ORScionAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Relay's not getting the correct backward OR routing info")
	}

	chdrIn = relay3ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.DataTypeBackward {
		t.Fatalf("Wrong CHDR requester OR backward")
	}
	err = relay2.relayProcessDataTypeBackward(*relay3ORScionAnswerPacket, relay2ORScionAnswerPacket)
	if err != nil {
		t.Fatalf("Couldn't process the packet at relay, %v", err)
	}
	relaySizePayloadBackpath = len(relay2ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload)
	if initSizePayloadBackpath != relaySizePayloadBackpath {
		t.Fatalf("Payloads size not constant on the path back: %v vs %v", initSizePayloadBackpath, relay2ORScionAnswerPacket)
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[2].Path, []byte("back")), core.DataplanePathToBytes(relay2ORScionAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Relay's not getting the correct backward OR routing info")
	}

	chdrIn = relay2ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.DataTypeBackward {
		t.Fatalf("Wrong CHDR requester OR backward")
	}

	dnsAnswer, err := requester.onionDecrypt(relay2ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload)
	if err != nil {
		t.Fatalf("Couldn't decrypt the onion at requester")
	}

	if !bytes.Equal(dnsAnswer, []byte("success")) {
		fmt.Println(dnsAnswer)
		fmt.Println([]byte("success"))
		t.Fatalf("Onioning didn't work properly when decrypting at requester")
	}

}

// TestE2E3_2Relay tests the full process with 50 data transmission queries with a topology: Req->Rel2->Rel3->Rel4->Reso->Rel3->Rel2->Req
func TestE2E3_2Relay50Queries(t *testing.T) {
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// INIT NODES
	randReader, err := mocks.NewChachaEntropyReader(mocks.HardcodedChachaEntropyKeyStr)
	if err != nil {
		t.Fatalf("Can't get a ChachaEntropyReader")
	}
	requester := RequesterNode{
		node:                initNode(mocks.DefaultRequesterKeyStateHardcoded()),
		sessionDuration:     time.Duration(core.SessionDurationSeconds) * time.Second,
		session:             Session{},
		sphinxHeaderFactory: sphinxmixcrypto.NewMixHeaderFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded3_2(), randReader),
		sphinxPacketFactory: sphinxmixcrypto.NewSphinxPacketFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded3_2(), randReader),
	}
	pathingForward, pathingBackward := mocks.GetHardcodedHopByHopPath3_2Relay()
	requester.session.pathingForward = pathingForward
	requester.session.pathingBackward = pathingBackward
	err = requester.initSessionLocally()
	if err != nil {
		log.Println(err)
		t.Fatalf("requester couldn't init session locally")
	}
	relay2 := initNode(mocks.DefaultRelay2KeyStateHardcoded())
	relay3 := initNode(mocks.DefaultRelay3KeyStateHardcoded())
	relay4 := initNode(mocks.DefaultRelay1KeyStateHardcoded())
	resolver := initNode(mocks.DefaultResolverKeyStateHardcoded())

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// SPHINX
	requesterSphinxScionPacket, keyToInitiateForwardFSPayload, err := requester.setupSphinxSession_createScionPacket()
	if err != nil {
		t.Fatalf("requester couldn't create the scion packet")
	}

	relay2SphinxScionPacket := &snet.Packet{}
	relay3SphinxScionPacket := &snet.Packet{}
	relay4SphinxScionPacket := &snet.Packet{}
	resolverSphinxScionAnswerPacket := &snet.Packet{}
	relay3SphinxScionAnswerPacket := &snet.Packet{}
	relay2SphinxScionAnswerPacket := &snet.Packet{}

	chdrIn := requesterSphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR relay sphinx")
	}
	err = relay2.relayProcessSphinxSetup(requesterSphinxScionPacket, relay2SphinxScionPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[1].Path, []byte("forw")), core.DataplanePathToBytes(relay2SphinxScionPacket.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct routing info")
	}

	chdrIn = relay2SphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR resolver sphinx")
	}
	err = relay3.relayProcessSphinxSetup(*relay2SphinxScionPacket, relay3SphinxScionPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[2].Path, []byte("forw")), core.DataplanePathToBytes(relay3SphinxScionPacket.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct routing info")
	}

	chdrIn = relay3SphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR resolver sphinx")
	}
	err = relay4.relayProcessSphinxSetup(*relay3SphinxScionPacket, relay4SphinxScionPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[3].Path, []byte("forw")), core.DataplanePathToBytes(relay4SphinxScionPacket.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct routing info")
	}

	chdrIn = relay4SphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR resolver sphinx")
	}
	err = resolver.resolverProcessSphinxSetup(*relay4SphinxScionPacket, resolverSphinxScionAnswerPacket)
	if err != nil {
		t.Fatalf("Resolver couldn't process the packet")
	}

	/*resolverRawSphinxAnswerPacket := resolverSphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload
	resolverSphinxAnswerPacket := bytesToSetupPacket(resolverRawSphinxAnswerPacket)
	_ = resolverSphinxAnswerPacket.SphinxPayload
	_ = resolverSphinxAnswerPacket.FSPayload*/

	/*
		This check makes sense, but requires a change in API just for the test.
		I did it when refactoring, but not willing to clutter my code just to facilitate one check.
		resolverRawSphinxAnswerPacket := resolverSphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload
		resolverSphinxAnswerPacket := bytesToSetupPacket(resolverRawSphinxAnswerPacket)

		if !bytes.Equal(sphinxHeaderToBytes(resolverSphinxAnswerPacket.SphinxHDR), sphinxHeaderToBytes(SHDRb)) {
			t.Fatalf("SHDRb are not equal")
		}
	*/

	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[0].Path, []byte("back")), core.DataplanePathToBytes(resolverSphinxScionAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Resolver's not getting the correct routing info")
	}

	chdrIn = resolverSphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR relay sphinx")
	}
	err = relay3.relayProcessSphinxSetup(*resolverSphinxScionAnswerPacket, relay3SphinxScionAnswerPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the backward packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[1].Path, []byte("back")), core.DataplanePathToBytes(relay3SphinxScionAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Relay's not getting the correct backward routing info")
	}

	chdrIn = relay3SphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR relay sphinx")
	}
	err = relay2.relayProcessSphinxSetup(*relay3SphinxScionAnswerPacket, relay2SphinxScionAnswerPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the backward packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[2].Path, []byte("back")), core.DataplanePathToBytes(relay2SphinxScionAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Relay's not getting the correct backward routing info")
	}

	chdrIn = relay2SphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
	if chdrIn[0] != core.SetupType {
		t.Fatalf("Wrong CHDR relay sphinx")
	}
	err = requester.setupSphinxSession_processAnswerAndGetFSes(*relay2SphinxScionAnswerPacket, keyToInitiateForwardFSPayload)
	if err != nil {
		t.Fatalf("Requester couldn't process the answer")
	}

	// check correct FSes, but they are not exported by my API,
	// so I'll instead print them through the actual function addFStoPayload, which should not make it to prod.
	for i, FS := range requester.session.FSForward {
		log.Printf("%v: %v\n", i, FS)
	}
	for i, FS := range requester.session.FSBackward {
		log.Printf("%v: %v\n", i, FS)
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// Requester should have a valid session now, send a DNS request
	// ONION ROUTING HORNET-LIKE

	for i := 0; i < 50; i++ {
		originalDNSPayload := crypto.GeneratePseudoRandomDNSBytes()
		requesterORScionPacket, err := CreateOnion(originalDNSPayload, requester.session)
		if err != nil {
			log.Println(err)
			t.Fatalf("Onion creation unsuccessful")
		}

		initSizePayload := len(requesterORScionPacket.Payload.(snet.UDPPayload).Payload)

		chdrIn = requesterORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.DataTypeForward {
			t.Fatalf("Wrong CHDR relay OR")
		}

		relay2ORScionPacket := &snet.Packet{}
		relay3ORScionPacket := &snet.Packet{}
		relay4ORScionPacket := &snet.Packet{}
		resolverORScionAnswerPacket := &snet.Packet{}
		relay3ORScionAnswerPacket := &snet.Packet{}
		relay2ORScionAnswerPacket := &snet.Packet{}

		err = relay2.relayProcessDataTypeForward(requesterORScionPacket, relay2ORScionPacket)
		if err != nil {
			log.Println(err)
			t.Fatalf("relay2 couldn't process the onion forward")
		}
		intermediateSizePayload := len(relay2ORScionPacket.Payload.(snet.UDPPayload).Payload)
		if initSizePayload != intermediateSizePayload {
			t.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, intermediateSizePayload)
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingForward[1].Path, []byte("forw")), core.DataplanePathToBytes(relay2ORScionPacket.Path, []byte("forw"))) {
			t.Fatalf("Relay's not getting the correct forward OR routing info")
		}

		chdrIn = relay2ORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.DataTypeForward {
			t.Fatalf("Wrong CHDR resolver OR")
		}
		err = relay3.relayProcessDataTypeForward(*relay2ORScionPacket, relay3ORScionPacket)
		if err != nil {
			log.Println(err)
			t.Fatalf("relay3 couldn't process the onion forward")
		}
		intermediateSizePayload = len(relay3ORScionPacket.Payload.(snet.UDPPayload).Payload)
		if initSizePayload != intermediateSizePayload {
			t.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, intermediateSizePayload)
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingForward[2].Path, []byte("forw")), core.DataplanePathToBytes(relay3ORScionPacket.Path, []byte("forw"))) {
			t.Fatalf("Relay's not getting the correct forward OR routing info")
		}

		chdrIn = relay3ORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.DataTypeForward {
			t.Fatalf("Wrong CHDR resolver OR")
		}
		err = relay4.relayProcessDataTypeForward(*relay3ORScionPacket, relay4ORScionPacket)
		if err != nil {
			log.Println(err)
			t.Fatalf("relay4 couldn't process tWhe onion forward")
		}
		intermediateSizePayload = len(relay4ORScionPacket.Payload.(snet.UDPPayload).Payload)
		if initSizePayload != intermediateSizePayload {
			t.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, intermediateSizePayload)
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingForward[3].Path, []byte("forw")), core.DataplanePathToBytes(relay4ORScionPacket.Path, []byte("forw"))) {
			t.Fatalf("Relay's not getting the correct forward OR routing info")
		}

		chdrIn = relay4ORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.DataTypeForward {
			t.Fatalf("Wrong CHDR resolver OR")
		}

		finalPayload, R, sharedKey, err := resolver.removeLayer(relay4ORScionPacket.Payload.(snet.UDPPayload).Payload, true)
		if err != nil {
			t.Fatalf("Couldn't decrypt the packet at resolver, %v", err)
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[0].Path, []byte("back")), R) {
			t.Fatalf("Resolver's not getting the correct OR routing info")
		}

		decryptedPayload := finalPayload[core.CHDRLength:]

		//AHDRf := decryptedPayload[:core.AHDRLength] // This is garbage randomness, as there's no more FS/next routing
		AHDRb := decryptedPayload[core.AHDRLength : 2*core.AHDRLength]
		query := decryptedPayload[2*core.AHDRLength : len(decryptedPayload)-core.SecurityParameter]
		IV0b := decryptedPayload[len(decryptedPayload)-core.SecurityParameter:]

		if !bytes.Equal(originalDNSPayload, query) {
			fmt.Println(originalDNSPayload)
			fmt.Println(query)
			t.Fatalf("Onioning didn't work properly when decrypting query at resolver ")
		}

		originalDNSAnswer := []byte("success")

		// As per testHelpers.go prepareFakeSessionSymKeys comment, the symKey for the encryption as resolver == the symKey for the decryption
		O0b, err := crypto.ENC(sharedKey, IV0b, originalDNSAnswer, core.DataPaddingFactor, true)
		if err != nil {
			t.Fatalf("Couldn't encrypt the first layer of the onion back")
		}
		chdr := make([]byte, 0)
		chdr = append(chdr, core.DataTypeBackward, core.MaxPathLength)
		chdr = append(chdr, IV0b...)
		payloadBack := append(chdr, AHDRb...)
		payloadBack = append(payloadBack, O0b...)
		if !bytes.Contains(payloadBack, AHDRb) {
			t.Fatalf("Weird issue where AHDRb loses integrity")
		}

		initSizePayloadBackpath := len(payloadBack)

		udpPayload := snet.UDPPayload{
			SrcPort: 04104,
			DstPort: 04104,
			Payload: payloadBack,
		}
		resolverORScionAnswerPacket.Payload = udpPayload
		resolverORScionAnswerPacket.Path, _ = core.RoutingBytesToDataplanePath(R)

		chdrIn = resolverORScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.DataTypeBackward {
			t.Fatalf("Wrong CHDR relay OR backward")
		}

		// relay side
		err = relay3.relayProcessDataTypeBackward(*resolverORScionAnswerPacket, relay3ORScionAnswerPacket)
		if err != nil {
			t.Fatalf("Couldn't process the packet at relay, %v", err)
		}
		relaySizePayloadBackpath := len(relay3ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload)
		if initSizePayloadBackpath != relaySizePayloadBackpath {
			t.Fatalf("Payloads size not constant on the path back: %v vs %v", initSizePayloadBackpath, relaySizePayloadBackpath)
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[1].Path, []byte("back")), core.DataplanePathToBytes(relay3ORScionAnswerPacket.Path, []byte("back"))) {
			t.Fatalf("Relay's not getting the correct backward OR routing info")
		}

		chdrIn = relay3ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.DataTypeBackward {
			t.Fatalf("Wrong CHDR requester OR backward")
		}
		err = relay2.relayProcessDataTypeBackward(*relay3ORScionAnswerPacket, relay2ORScionAnswerPacket)
		if err != nil {
			t.Fatalf("Couldn't process the packet at relay, %v", err)
		}
		relaySizePayloadBackpath = len(relay2ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload)
		if initSizePayloadBackpath != relaySizePayloadBackpath {
			t.Fatalf("Payloads size not constant on the path back: %v vs %v", initSizePayloadBackpath, relay2ORScionAnswerPacket)
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[2].Path, []byte("back")), core.DataplanePathToBytes(relay2ORScionAnswerPacket.Path, []byte("back"))) {
			t.Fatalf("Relay's not getting the correct backward OR routing info")
		}

		chdrIn = relay2ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.DataTypeBackward {
			t.Fatalf("Wrong CHDR requester OR backward")
		}

		dnsAnswer, err := requester.onionDecrypt(relay2ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload)
		if err != nil {
			t.Fatalf("Couldn't decrypt the onion at requester")
		}

		if !bytes.Equal(dnsAnswer, []byte("success")) {
			fmt.Println(dnsAnswer)
			fmt.Println([]byte("success"))
			t.Fatalf("Onioning didn't work properly when decrypting at requester")
		}
	}
}

// BenchmarkE2E3_2Relay50Queries benchmarks the full process with 50 data transmission queries with a topology: Req->Rel2->Rel3->Rel4->Reso->Rel3->Rel2->Req
func BenchmarkE2E3_2Relay50Queries(b *testing.B) {
	for i := 0; i < b.N; i++ {
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// INIT NODES
		randReader, err := mocks.NewChachaEntropyReader(mocks.HardcodedChachaEntropyKeyStr)
		if err != nil {
			b.Fatalf("Can't get a ChachaEntropyReader")
		}
		requester := RequesterNode{
			node:                initNode(mocks.DefaultRequesterKeyStateHardcoded()),
			sessionDuration:     time.Duration(core.SessionDurationSeconds) * time.Second,
			session:             Session{},
			sphinxHeaderFactory: sphinxmixcrypto.NewMixHeaderFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded3_2(), randReader),
			sphinxPacketFactory: sphinxmixcrypto.NewSphinxPacketFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded3_2(), randReader),
		}
		pathingForward, pathingBackward := mocks.GetHardcodedHopByHopPath3_2Relay()
		requester.session.pathingForward = pathingForward
		requester.session.pathingBackward = pathingBackward
		err = requester.initSessionLocally()
		if err != nil {
			log.Println(err)
			b.Fatalf("requester couldn't init session locally")
		}
		relay2 := initNode(mocks.DefaultRelay2KeyStateHardcoded())
		relay3 := initNode(mocks.DefaultRelay3KeyStateHardcoded())
		relay4 := initNode(mocks.DefaultRelay1KeyStateHardcoded())
		resolver := initNode(mocks.DefaultResolverKeyStateHardcoded())

		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// SPHINX
		requesterSphinxScionPacket, keyToInitiateForwardFSPayload, err := requester.setupSphinxSession_createScionPacket()
		if err != nil {
			b.Fatalf("requester couldn't create the scion packet")
		}

		relay2SphinxScionPacket := &snet.Packet{}
		relay3SphinxScionPacket := &snet.Packet{}
		relay4SphinxScionPacket := &snet.Packet{}
		resolverSphinxScionAnswerPacket := &snet.Packet{}
		relay3SphinxScionAnswerPacket := &snet.Packet{}
		relay2SphinxScionAnswerPacket := &snet.Packet{}

		chdrIn := requesterSphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.SetupType {
			b.Fatalf("Wrong CHDR relay sphinx")
		}
		err = relay2.relayProcessSphinxSetup(requesterSphinxScionPacket, relay2SphinxScionPacket)
		if err != nil {
			b.Fatalf("Relay couldn't process the packet")
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingForward[1].Path, []byte("forw")), core.DataplanePathToBytes(relay2SphinxScionPacket.Path, []byte("forw"))) {
			b.Fatalf("Relay's not getting the correct routing info")
		}

		chdrIn = relay2SphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.SetupType {
			b.Fatalf("Wrong CHDR resolver sphinx")
		}
		err = relay3.relayProcessSphinxSetup(*relay2SphinxScionPacket, relay3SphinxScionPacket)
		if err != nil {
			b.Fatalf("Relay couldn't process the packet")
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingForward[2].Path, []byte("forw")), core.DataplanePathToBytes(relay3SphinxScionPacket.Path, []byte("forw"))) {
			b.Fatalf("Relay's not getting the correct routing info")
		}

		chdrIn = relay3SphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.SetupType {
			b.Fatalf("Wrong CHDR resolver sphinx")
		}
		err = relay4.relayProcessSphinxSetup(*relay3SphinxScionPacket, relay4SphinxScionPacket)
		if err != nil {
			b.Fatalf("Relay couldn't process the packet")
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingForward[3].Path, []byte("forw")), core.DataplanePathToBytes(relay4SphinxScionPacket.Path, []byte("forw"))) {
			b.Fatalf("Relay's not getting the correct routing info")
		}

		chdrIn = relay4SphinxScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.SetupType {
			b.Fatalf("Wrong CHDR resolver sphinx")
		}
		err = resolver.resolverProcessSphinxSetup(*relay4SphinxScionPacket, resolverSphinxScionAnswerPacket)
		if err != nil {
			b.Fatalf("Resolver couldn't process the packet")
		}

		/*resolverRawSphinxAnswerPacket := resolverSphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload
		resolverSphinxAnswerPacket := bytesToSetupPacket(resolverRawSphinxAnswerPacket)
		_ = resolverSphinxAnswerPacket.SphinxPayload
		_ = resolverSphinxAnswerPacket.FSPayload*/

		/*
			This check makes sense, but requires a change in API just for the test.
			I did it when refactoring, but not willing to clutter my code just to facilitate one check.
			resolverRawSphinxAnswerPacket := resolverSphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload
			resolverSphinxAnswerPacket := bytesToSetupPacket(resolverRawSphinxAnswerPacket)

			if !bytes.Equal(sphinxHeaderToBytes(resolverSphinxAnswerPacket.SphinxHDR), sphinxHeaderToBytes(SHDRb)) {
				b.Fatalf("SHDRb are not equal")
			}
		*/

		if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[0].Path, []byte("back")), core.DataplanePathToBytes(resolverSphinxScionAnswerPacket.Path, []byte("back"))) {
			b.Fatalf("Resolver's not getting the correct routing info")
		}

		chdrIn = resolverSphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.SetupType {
			b.Fatalf("Wrong CHDR relay sphinx")
		}
		err = relay3.relayProcessSphinxSetup(*resolverSphinxScionAnswerPacket, relay3SphinxScionAnswerPacket)
		if err != nil {
			b.Fatalf("Relay couldn't process the backward packet")
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[1].Path, []byte("back")), core.DataplanePathToBytes(relay3SphinxScionAnswerPacket.Path, []byte("back"))) {
			b.Fatalf("Relay's not getting the correct backward routing info")
		}

		chdrIn = relay3SphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.SetupType {
			b.Fatalf("Wrong CHDR relay sphinx")
		}
		err = relay2.relayProcessSphinxSetup(*relay3SphinxScionAnswerPacket, relay2SphinxScionAnswerPacket)
		if err != nil {
			b.Fatalf("Relay couldn't process the backward packet")
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[2].Path, []byte("back")), core.DataplanePathToBytes(relay2SphinxScionAnswerPacket.Path, []byte("back"))) {
			b.Fatalf("Relay's not getting the correct backward routing info")
		}

		chdrIn = relay2SphinxScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		if chdrIn[0] != core.SetupType {
			b.Fatalf("Wrong CHDR relay sphinx")
		}
		err = requester.setupSphinxSession_processAnswerAndGetFSes(*relay2SphinxScionAnswerPacket, keyToInitiateForwardFSPayload)
		if err != nil {
			b.Fatalf("Requester couldn't process the answer")
		}

		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// Requester should have a valid session now, send a DNS request
		// ONION ROUTING HORNET-LIKE

		for i := 0; i < 50; i++ {
			originalDNSPayload := crypto.GeneratePseudoRandomDNSBytes()
			requesterORScionPacket, err := CreateOnion(originalDNSPayload, requester.session)
			if err != nil {
				log.Println(err)
				b.Fatalf("Onion creation unsuccessful")
			}

			initSizePayload := len(requesterORScionPacket.Payload.(snet.UDPPayload).Payload)

			chdrIn = requesterORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
			if chdrIn[0] != core.DataTypeForward {
				b.Fatalf("Wrong CHDR relay OR")
			}

			relay2ORScionPacket := &snet.Packet{}
			relay3ORScionPacket := &snet.Packet{}
			relay4ORScionPacket := &snet.Packet{}
			resolverORScionAnswerPacket := &snet.Packet{}
			relay3ORScionAnswerPacket := &snet.Packet{}
			relay2ORScionAnswerPacket := &snet.Packet{}

			err = relay2.relayProcessDataTypeForward(requesterORScionPacket, relay2ORScionPacket)
			if err != nil {
				log.Println(err)
				b.Fatalf("relay2 couldn't process the onion forward")
			}
			intermediateSizePayload := len(relay2ORScionPacket.Payload.(snet.UDPPayload).Payload)
			if initSizePayload != intermediateSizePayload {
				b.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, intermediateSizePayload)
			}
			if !bytes.Equal(core.DataplanePathToBytes(pathingForward[1].Path, []byte("forw")), core.DataplanePathToBytes(relay2ORScionPacket.Path, []byte("forw"))) {
				b.Fatalf("Relay's not getting the correct forward OR routing info")
			}

			chdrIn = relay2ORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
			if chdrIn[0] != core.DataTypeForward {
				b.Fatalf("Wrong CHDR resolver OR")
			}
			err = relay3.relayProcessDataTypeForward(*relay2ORScionPacket, relay3ORScionPacket)
			if err != nil {
				log.Println(err)
				b.Fatalf("relay3 couldn't process the onion forward")
			}
			intermediateSizePayload = len(relay3ORScionPacket.Payload.(snet.UDPPayload).Payload)
			if initSizePayload != intermediateSizePayload {
				b.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, intermediateSizePayload)
			}
			if !bytes.Equal(core.DataplanePathToBytes(pathingForward[2].Path, []byte("forw")), core.DataplanePathToBytes(relay3ORScionPacket.Path, []byte("forw"))) {
				b.Fatalf("Relay's not getting the correct forward OR routing info")
			}

			chdrIn = relay3ORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
			if chdrIn[0] != core.DataTypeForward {
				b.Fatalf("Wrong CHDR resolver OR")
			}
			err = relay4.relayProcessDataTypeForward(*relay3ORScionPacket, relay4ORScionPacket)
			if err != nil {
				log.Println(err)
				b.Fatalf("relay4 couldn't process tWhe onion forward")
			}
			intermediateSizePayload = len(relay4ORScionPacket.Payload.(snet.UDPPayload).Payload)
			if initSizePayload != intermediateSizePayload {
				b.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, intermediateSizePayload)
			}
			if !bytes.Equal(core.DataplanePathToBytes(pathingForward[3].Path, []byte("forw")), core.DataplanePathToBytes(relay4ORScionPacket.Path, []byte("forw"))) {
				b.Fatalf("Relay's not getting the correct forward OR routing info")
			}

			chdrIn = relay4ORScionPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
			if chdrIn[0] != core.DataTypeForward {
				b.Fatalf("Wrong CHDR resolver OR")
			}

			finalPayload, R, sharedKey, err := resolver.removeLayer(relay4ORScionPacket.Payload.(snet.UDPPayload).Payload, true)
			if err != nil {
				b.Fatalf("Couldn't decrypt the packet at resolver, %v", err)
			}
			if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[0].Path, []byte("back")), R) {
				b.Fatalf("Resolver's not getting the correct OR routing info")
			}

			decryptedPayload := finalPayload[core.CHDRLength:]

			//AHDRf := decryptedPayload[:core.AHDRLength] // This is garbage randomness, as there's no more FS/next routing
			AHDRb := decryptedPayload[core.AHDRLength : 2*core.AHDRLength]
			query := decryptedPayload[2*core.AHDRLength : len(decryptedPayload)-core.SecurityParameter]
			IV0b := decryptedPayload[len(decryptedPayload)-core.SecurityParameter:]

			if !bytes.Equal(originalDNSPayload, query) {
				fmt.Println(originalDNSPayload)
				fmt.Println(query)
				b.Fatalf("Onioning didn't work properly when decrypting query at resolver ")
			}

			originalDNSAnswer := []byte("success")

			// As per testHelpers.go prepareFakeSessionSymKeys comment, the symKey for the encryption as resolver == the symKey for the decryption
			O0b, err := crypto.ENC(sharedKey, IV0b, originalDNSAnswer, core.DataPaddingFactor, true)
			if err != nil {
				b.Fatalf("Couldn't encrypt the first layer of the onion back")
			}
			chdr := make([]byte, 0)
			chdr = append(chdr, core.DataTypeBackward, core.MaxPathLength)
			chdr = append(chdr, IV0b...)
			payloadBack := append(chdr, AHDRb...)
			payloadBack = append(payloadBack, O0b...)
			if !bytes.Contains(payloadBack, AHDRb) {
				b.Fatalf("Weird issue where AHDRb loses integrity")
			}

			initSizePayloadBackpath := len(payloadBack)

			udpPayload := snet.UDPPayload{
				SrcPort: 04104,
				DstPort: 04104,
				Payload: payloadBack,
			}
			resolverORScionAnswerPacket.Payload = udpPayload
			resolverORScionAnswerPacket.Path, _ = core.RoutingBytesToDataplanePath(R)

			chdrIn = resolverORScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
			if chdrIn[0] != core.DataTypeBackward {
				b.Fatalf("Wrong CHDR relay OR backward")
			}

			// relay side
			err = relay3.relayProcessDataTypeBackward(*resolverORScionAnswerPacket, relay3ORScionAnswerPacket)
			if err != nil {
				b.Fatalf("Couldn't process the packet at relay, %v", err)
			}
			relaySizePayloadBackpath := len(relay3ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload)
			if initSizePayloadBackpath != relaySizePayloadBackpath {
				b.Fatalf("Payloads size not constant on the path back: %v vs %v", initSizePayloadBackpath, relaySizePayloadBackpath)
			}
			if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[1].Path, []byte("back")), core.DataplanePathToBytes(relay3ORScionAnswerPacket.Path, []byte("back"))) {
				b.Fatalf("Relay's not getting the correct backward OR routing info")
			}

			chdrIn = relay3ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
			if chdrIn[0] != core.DataTypeBackward {
				b.Fatalf("Wrong CHDR requester OR backward")
			}
			err = relay2.relayProcessDataTypeBackward(*relay3ORScionAnswerPacket, relay2ORScionAnswerPacket)
			if err != nil {
				b.Fatalf("Couldn't process the packet at relay, %v", err)
			}
			relaySizePayloadBackpath = len(relay2ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload)
			if initSizePayloadBackpath != relaySizePayloadBackpath {
				b.Fatalf("Payloads size not constant on the path back: %v vs %v", initSizePayloadBackpath, relay2ORScionAnswerPacket)
			}
			if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[2].Path, []byte("back")), core.DataplanePathToBytes(relay2ORScionAnswerPacket.Path, []byte("back"))) {
				b.Fatalf("Relay's not getting the correct backward OR routing info")
			}

			chdrIn = relay2ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
			if chdrIn[0] != core.DataTypeBackward {
				b.Fatalf("Wrong CHDR requester OR backward")
			}

			dnsAnswer, err := requester.onionDecrypt(relay2ORScionAnswerPacket.Payload.(snet.UDPPayload).Payload)
			if err != nil {
				b.Fatalf("Couldn't decrypt the onion at requester")
			}

			if !bytes.Equal(dnsAnswer, []byte("success")) {
				fmt.Println(dnsAnswer)
				fmt.Println([]byte("success"))
				b.Fatalf("Onioning didn't work properly when decrypting at requester")
			}
		}
	}
}
