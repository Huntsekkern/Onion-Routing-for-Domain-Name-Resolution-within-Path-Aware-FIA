package node

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"github.com/scionproto/scion/pkg/snet"
	"log"
	"main.go/core"
	"main.go/crypto"
	"main.go/go-sphinxmixcrypto"
	"main.go/mocks"
	"testing"
	"time"
)

// Test8_16bytesSwitch checks that the way I cut down bytes works well
func Test8_16bytesSwitch(t *testing.T) {
	duration := time.Duration(30)
	EXP := time.Now().Add(duration).Unix()

	chdr := core.CHDR{
		Type:    core.SetupType,
		Hops:    core.MaxPathLength,
		IVorEXP: core.DurationToEXPBytes(duration),
	}

	recoveredEXPBytes := core.BytesEXPToFSExpField(chdr.IVorEXP)
	retrievedEXP := binary.BigEndian.Uint64(recoveredEXPBytes)

	if int64(retrievedEXP) != EXP {
		t.Fatalf("Fix code in sphinx.go processSphinxSetup")
	}
}

// TestAddAndRetrieveFSes checks the function addFStoPayload and retrieveFSes
func TestAddAndRetrieveFSes(t *testing.T) {
	session := generateExampleSessionFromPathing(mocks.GetHardcodedHopByHopPath())

	relay := Node{}
	relay.secretKey = make([]byte, core.SecurityParameter)
	_, err := rand.Read(relay.secretKey)
	if err != nil {
		t.Fatalf("Couldn't read randomness for the secretKey. Node not running, %v", err)
	}
	resolver := Node{}
	resolver.secretKey = make([]byte, core.SecurityParameter)
	_, err = rand.Read(resolver.secretKey)
	if err != nil {
		t.Fatalf("Couldn't read randomness for the secretKey. Node not running, %v", err)
	}

	decryptedFS0 := crypto.GenerateExampleFSWithRandomRouting(session.sharedKeysForward[0])
	//debugPrintDecryptedFS(decryptedFS0, "testCreation, relay FS")
	decryptedFS1 := crypto.GenerateExampleFSWithRandomRouting(session.sharedKeysForward[1])
	encryptedFS0, err := crypto.PRP(relay.secretKey, decryptedFS0)
	if err != nil {
		t.Fatalf("Couldn't encrypt the first FS, %v", err)
	}
	encryptedFS1, err := crypto.PRP(resolver.secretKey, decryptedFS1)
	if err != nil {
		t.Fatalf("Couldn't encrypt the second FS, %v", err)
	}
	FSForward := make([][]byte, 2)
	FSForward[0] = encryptedFS0
	FSForward[1] = encryptedFS1
	session.FSForward = FSForward

	keyToInitiateForwardFSPayload := make([]byte, core.SecurityParameter)
	bytesAmount, err := rand.Read(keyToInitiateForwardFSPayload)
	if err != nil || bytesAmount != core.SecurityParameter {
		log.Println(err)
		t.Fatalf("Error while generating random SymKeys")

	}
	FSPayload0, err := crypto.PRG(keyToInitiateForwardFSPayload)
	if err != nil {
		log.Println(err)
		t.Fatalf("Couldn't initiate the FSPayload")
	}

	FSPayload1, err := addFStoPayload(session.sharedKeysForward[0], FSForward[0], FSPayload0)
	if err != nil {
		log.Println(err)
		t.Fatalf("Couldn't add the FS0")
	}

	FSPayload2, err := addFStoPayload(session.sharedKeysForward[1], FSForward[1], FSPayload1)
	if err != nil {
		log.Println(err)
		t.Fatalf("Couldn't add the FS1")
	}

	FSes, err := retrieveFSes(keyToInitiateForwardFSPayload, session.sharedKeysForward, FSPayload2)
	if err != nil {
		log.Println(err)
		t.Fatalf("Couldn't retrieve the FSes")
	}

	for i, FS := range FSes {
		if !bytes.Equal(FS, session.FSForward[i]) {
			t.Fatalf("FSes do not match")
		}
	}

}

// initRequesterRelayResolverForTestSphinx1Relay initialises 3 nodes for a single relay topology.
func initRequesterRelayResolverForTestSphinx1Relay(t *testing.T) (requester RequesterNode, relay Node, resolver Node) {
	relay = initNode(mocks.DefaultRelay1KeyStateHardcoded())

	resolver = initNode(mocks.DefaultResolverKeyStateHardcoded())

	////////////////////////////////////
	requester = RequesterNode{
		node:                initNode(mocks.DefaultRequesterKeyStateHardcoded()),
		sessionDuration:     0,
		session:             Session{},
		sphinxHeaderFactory: nil,
		sphinxPacketFactory: nil,
	}

	requester.sessionDuration = time.Duration(core.SessionDurationSeconds) * time.Second

	randReader, err := mocks.NewChachaEntropyReader(mocks.HardcodedChachaEntropyKeyStr)
	if err != nil {
		log.Println("Can't get a ChachaEntropyReader")
	}

	// PKI must be a map from "address" (node routing information) to their asymPublicKey. Assumed by HORNET to be already known so I can hardcode it here.
	requester.sphinxHeaderFactory = sphinxmixcrypto.NewMixHeaderFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded(), randReader)
	requester.sphinxPacketFactory = sphinxmixcrypto.NewSphinxPacketFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded(), randReader)

	pathingForward, pathingBackward := mocks.GetHardcodedHopByHopPath()
	requester.session.pathingForward = pathingForward
	requester.session.pathingBackward = pathingBackward
	err = requester.initSessionLocally()
	if err != nil {
		log.Println(err)
		t.Fatalf("requester couldn't init session locally")
	}

	return requester, relay, resolver
}

// initRequesterRelayResolverForTestSphinx3_2Relay initialises 5 nodes for a 3 hops forward - 2 hops backward topology.
func initRequesterRelayResolverForTestSphinx3_2Relay(t testing.TB) (requester RequesterNode, relay2, relay3, relay4 Node, resolver Node) {
	relay4 = initNode(mocks.DefaultRelay1KeyStateHardcoded())
	relay2 = initNode(mocks.DefaultRelay2KeyStateHardcoded())
	relay3 = initNode(mocks.DefaultRelay3KeyStateHardcoded())

	resolver = initNode(mocks.DefaultResolverKeyStateHardcoded())

	////////////////////////////////////
	requester = RequesterNode{
		node:                initNode(mocks.DefaultRequesterKeyStateHardcoded()),
		sessionDuration:     0,
		session:             Session{},
		sphinxHeaderFactory: nil,
		sphinxPacketFactory: nil,
	}

	requester.sessionDuration = time.Duration(core.SessionDurationSeconds) * time.Second

	randReader, err := mocks.NewChachaEntropyReader(mocks.HardcodedChachaEntropyKeyStr)
	if err != nil {
		log.Println("Can't get a ChachaEntropyReader")
	}

	// PKI must be a map from "address" (node routing information) to their asymPublicKey. Assumed by HORNET to be already known so I can hardcode it here.
	requester.sphinxHeaderFactory = sphinxmixcrypto.NewMixHeaderFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded3_2(), randReader)
	requester.sphinxPacketFactory = sphinxmixcrypto.NewSphinxPacketFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded3_2(), randReader)

	pathingForward, pathingBackward := mocks.GetHardcodedHopByHopPath3_2Relay()
	requester.session.pathingForward = pathingForward
	requester.session.pathingBackward = pathingBackward
	err = requester.initSessionLocally()
	if err != nil {
		log.Println(err)
		t.Fatalf("requester couldn't init session locally")
	}

	return requester, relay2, relay3, relay4, resolver
}

// TestSphinxOneWay1Relay calls the functions manipulating the sphinx payloads
func TestSphinxOneWay1Relay(t *testing.T) {
	requester, relay, resolver := initRequesterRelayResolverForTestSphinx1Relay(t)

	pathingForward, _ := mocks.GetHardcodedHopByHopPath()

	CHDR := core.CHDR{
		Type:    core.SetupType,
		Hops:    core.MaxPathLength,
		IVorEXP: core.DurationToEXPBytes(requester.sessionDuration),
	}

	SHDRf, SHDRb, err, sharedSecretsForward32bytes := requester.generateSphinxHeaders(&requester.session, CHDR)
	if err != nil {
		t.Fatalf("Couldn't generate sphinx headers")
	}

	sphinxPayloadf, err := requester.generateSphinxPayloadForward(sharedSecretsForward32bytes, SHDRf, SHDRb)
	if err != nil {
		t.Fatalf("Couldn't generate sphinx payload forward")
	}

	relayHDR, relayPayload, _, postRelayRouting, err := relay.processSphinxPacket(SHDRf, sphinxPayloadf)
	if err != nil {
		t.Fatalf("Relay couldn't process the packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[1].Path, []byte("forw")), postRelayRouting) {
		t.Fatalf("Relay's not getting the correct routing info")
	}

	_, resolverPayload, sharedKey, _, err := resolver.processSphinxPacket(relayHDR, relayPayload)
	if err != nil {
		t.Fatalf("Resolver couldn't process the packet")
	}

	if bytes.Equal(resolverPayload, core.SphinxHeaderToBytes(SHDRb)) {
		// Well, so this passed, which might be good, although it forces me to deviate a bit from HORNET structure.
		t.Logf("No need to unwrapSphinxPayloadAtDest, review code logic to fit the library")
	}

	receivedSHDRb, err := unwrapSphinxPayloadAtDest(sharedKey, resolverPayload)
	if err != nil {
		t.Fatalf("Couldn't unwrap sphinx payload at dest")
	}

	if !bytes.Equal(core.SphinxHeaderToBytes(receivedSHDRb), core.SphinxHeaderToBytes(SHDRb)) {
		t.Fatalf("SHDRb are not equal")
	}

}

// TestSphinxOneWay1RelayNodeLevel calls the functions manipulating the snet.Packet
func TestSphinxOneWay1RelayNodeLevel(t *testing.T) {
	requester, relay, resolver := initRequesterRelayResolverForTestSphinx1Relay(t)

	pathingForward, pathingBackward := mocks.GetHardcodedHopByHopPath()

	// This is done 1 layer above the previous test

	requesterPacket, _, err := requester.setupSphinxSession_createScionPacket()
	if err != nil {
		t.Fatalf("requester couldn't create the scion packet")
	}

	relayPacket := &snet.Packet{}
	resolverAnswerPacket := &snet.Packet{}

	err = relay.relayProcessSphinxSetup(requesterPacket, relayPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[1].Path, []byte("forw")), core.DataplanePathToBytes(relayPacket.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct routing info")
	}

	err = resolver.resolverProcessSphinxSetup(*relayPacket, resolverAnswerPacket)
	if err != nil {
		t.Fatalf("Resolver couldn't process the packet")
	}

	/*
		This check makes sense, but requires a change in API just for the test.
		I did it when refactoring, but not willing to clutter my code just to facilitate one check.
		resolverRawSphinxAnswerPacket := resolverAnswerPacket.Payload.(snet.UDPPayload).Payload
		resolverSphinxAnswerPacket := bytesToSetupPacket(resolverRawSphinxAnswerPacket)

		if !bytes.Equal(sphinxHeaderToBytes(resolverSphinxAnswerPacket.SphinxHDR), sphinxHeaderToBytes(SHDRb)) {
			t.Fatalf("SHDRb are not equal")
		}
	*/

	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[0].Path, []byte("back")), core.DataplanePathToBytes(resolverAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Resolver's not getting the correct routing info")
	}

}

// TestUnderstandingOfLioness verifies that Lioness is a PRP
func TestUnderstandingOfLioness(t *testing.T) {
	sharedKey32 := make([]byte, 32)

	keyToInitiateForwardFSPayload := make([]byte, core.SecurityParameter)
	bytesAmount, err := rand.Read(keyToInitiateForwardFSPayload)
	if err != nil || bytesAmount != core.SecurityParameter {
		log.Println(err)
		t.Fatalf("Error while generating random SymKeys")
	}
	FSPayloadForward, err := crypto.PRG(keyToInitiateForwardFSPayload)
	if err != nil {
		t.Fatalf("Couldn't initiate the FSPayload")
	}

	blockCipherDest := sphinxmixcrypto.NewLionessBlockCipher()
	deltaKey, err := blockCipherDest.CreateBlockCipherKey(*(*[32]byte)(sharedKey32))
	if err != nil {
		t.Fatalf("createBlockCipherKey failure: %s", err)
	}
	payloadDecrypted, err := blockCipherDest.Decrypt(deltaKey, FSPayloadForward)
	if err != nil {
		t.Fatalf("123 wide block cipher decryption failure: %s", err)
	}

	blockCipherSource := sphinxmixcrypto.NewLionessBlockCipher()
	blockCipherKey, err := blockCipherSource.CreateBlockCipherKey(*(*[32]byte)(sharedKey32))
	if err != nil {
		t.Fatalf("createBlockCipherKey failure: %s", err)
	}
	payloadEncrypted, err := blockCipherSource.Encrypt(blockCipherKey, payloadDecrypted)
	if err != nil {
		t.Fatalf("123 wide block cipher encryption failure: %s", err)
	}

	if !bytes.Equal(FSPayloadForward, payloadEncrypted) {
		t.Fatalf("encryption-decryption are not inversible")
	} else {
		t.Logf("Lioness can first decrypt plaintext then encrypt it, and recover the plaintext (It is a PRP)")
	}
}

// TestSphinxRoundTrip1RelayNodeLevel calls the function manipulating the snet.Packet
func TestSphinxRoundTrip1RelayNodeLevel(t *testing.T) {
	requester, relay, resolver := initRequesterRelayResolverForTestSphinx1Relay(t)

	pathingForward, pathingBackward := mocks.GetHardcodedHopByHopPath()

	// This is done 1 layer above

	requesterPacket, keyToInitiateForwardFSPayload, err := requester.setupSphinxSession_createScionPacket()
	if err != nil {
		t.Fatalf("requester couldn't create the scion packet")
	}

	relayPacket := &snet.Packet{}
	resolverAnswerPacket := &snet.Packet{}
	relayAnswerPacket := &snet.Packet{}

	err = relay.relayProcessSphinxSetup(requesterPacket, relayPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the packet")
	}

	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[1].Path, []byte("forw")), core.DataplanePathToBytes(relayPacket.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct routing info")
	}

	err = resolver.resolverProcessSphinxSetup(*relayPacket, resolverAnswerPacket)
	if err != nil {
		t.Fatalf("Resolver couldn't process the packet")
	}

	resolverRawSphinxAnswerPacket := resolverAnswerPacket.Payload.(snet.UDPPayload).Payload
	resolverSphinxAnswerPacket := core.BytesToSetupPacket(resolverRawSphinxAnswerPacket)
	_ = resolverSphinxAnswerPacket.SphinxPayload
	_ = resolverSphinxAnswerPacket.FSPayload

	/*
		This check makes sense, but requires a change in API just for the test.
		I did it when refactoring, but not willing to clutter my code just to facilitate one check.
		resolverRawSphinxAnswerPacket := resolverAnswerPacket.Payload.(snet.UDPPayload).Payload
		resolverSphinxAnswerPacket := bytesToSetupPacket(resolverRawSphinxAnswerPacket)

		if !bytes.Equal(sphinxHeaderToBytes(resolverSphinxAnswerPacket.SphinxHDR), sphinxHeaderToBytes(SHDRb)) {
			t.Fatalf("SHDRb are not equal")
		}
	*/

	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[0].Path, []byte("back")), core.DataplanePathToBytes(resolverAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Resolver's not getting the correct routing info")
	}

	err = relay.relayProcessSphinxSetup(*resolverAnswerPacket, relayAnswerPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the backward packet")
	}

	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[1].Path, []byte("back")), core.DataplanePathToBytes(relayAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Relay's not getting the correct backward routing info")
	}

	err = requester.setupSphinxSession_processAnswerAndGetFSes(*relayAnswerPacket, keyToInitiateForwardFSPayload)
	if err != nil {
		t.Fatalf("Requester couldn't process the answer")
	}

	// check correct FSes! Which is mostly the whole point of the whole process! It was already kind of guaranteed by the MAC though.
	// But again, they are not exported by my API, so I'll instead print them through the actual function addFStoPayload, which should not make it to prod.
	for i, FS := range requester.session.FSForward {
		log.Printf("%v: %v\n", i, FS)
	}
	for i, FS := range requester.session.FSBackward {
		log.Printf("%v: %v\n", i, FS)
	}

}

// TestSphinxRoundTrip3_2RelayNodeLevel tests the set-up phase with a topology: Req->Rel2->Rel3->Rel4->Reso->Rel3->Rel2-Req
// calling functions manipulating the snet.Packet
func TestSphinxRoundTrip3_2RelayNodeLevel(t *testing.T) {
	requester, relay2, relay3, relay4, resolver := initRequesterRelayResolverForTestSphinx3_2Relay(t)

	pathingForward, pathingBackward := mocks.GetHardcodedHopByHopPath3_2Relay()

	// This is done 1 layer above


	requesterPacket, keyToInitiateForwardFSPayload, err := requester.setupSphinxSession_createScionPacket()
	if err != nil {
		t.Fatalf("requester couldn't create the scion packet")
	}

	relay2Packet := &snet.Packet{}
	relay3Packet := &snet.Packet{}
	relay4Packet := &snet.Packet{}
	resolverAnswerPacket := &snet.Packet{}
	relay3AnswerPacket := &snet.Packet{}
	relay2AnswerPacket := &snet.Packet{}

	err = relay2.relayProcessSphinxSetup(requesterPacket, relay2Packet)
	if err != nil {
		t.Fatalf("Relay couldn't process the packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[1].Path, []byte("forw")), core.DataplanePathToBytes(relay2Packet.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct routing info")
	}

	err = relay3.relayProcessSphinxSetup(*relay2Packet, relay3Packet)
	if err != nil {
		t.Fatalf("Relay couldn't process the packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[2].Path, []byte("forw")), core.DataplanePathToBytes(relay3Packet.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct routing info")
	}

	err = relay4.relayProcessSphinxSetup(*relay3Packet, relay4Packet)
	if err != nil {
		t.Fatalf("Relay couldn't process the packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingForward[3].Path, []byte("forw")), core.DataplanePathToBytes(relay4Packet.Path, []byte("forw"))) {
		t.Fatalf("Relay's not getting the correct routing info")
	}

	err = resolver.resolverProcessSphinxSetup(*relay4Packet, resolverAnswerPacket)
	if err != nil {
		t.Fatalf("Resolver couldn't process the packet")
	}

	resolverRawSphinxAnswerPacket := resolverAnswerPacket.Payload.(snet.UDPPayload).Payload
	resolverSphinxAnswerPacket := core.BytesToSetupPacket(resolverRawSphinxAnswerPacket)
	_ = resolverSphinxAnswerPacket.SphinxPayload
	_ = resolverSphinxAnswerPacket.FSPayload

	/*
		This check makes sense, but requires a change in API just for the test.
		I did it when refactoring, but not willing to clutter my code just to facilitate one check.
		resolverRawSphinxAnswerPacket := resolverAnswerPacket.Payload.(snet.UDPPayload).Payload
		resolverSphinxAnswerPacket := bytesToSetupPacket(resolverRawSphinxAnswerPacket)

		if !bytes.Equal(sphinxHeaderToBytes(resolverSphinxAnswerPacket.SphinxHDR), sphinxHeaderToBytes(SHDRb)) {
			t.Fatalf("SHDRb are not equal")
		}
	*/

	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[0].Path, []byte("back")), core.DataplanePathToBytes(resolverAnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Resolver's not getting the correct routing info")
	}

	err = relay3.relayProcessSphinxSetup(*resolverAnswerPacket, relay3AnswerPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the backward packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[1].Path, []byte("back")), core.DataplanePathToBytes(relay3AnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Relay's not getting the correct backward routing info")
	}

	err = relay2.relayProcessSphinxSetup(*relay3AnswerPacket, relay2AnswerPacket)
	if err != nil {
		t.Fatalf("Relay couldn't process the backward packet")
	}
	if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[2].Path, []byte("back")), core.DataplanePathToBytes(relay2AnswerPacket.Path, []byte("back"))) {
		t.Fatalf("Relay's not getting the correct backward routing info")
	}

	err = requester.setupSphinxSession_processAnswerAndGetFSes(*relay2AnswerPacket, keyToInitiateForwardFSPayload)
	if err != nil {
		t.Fatalf("Requester couldn't process the answer")
	}

	// check correct FSes! Which is mostly the whole point of the whole process! It was already kind of guaranteed by the MAC though.
	// But again, they are not exported by my API, so I'll instead print them through the actual function addFStoPayload, which should not make it to prod.
	for i, FS := range requester.session.FSForward {
		log.Printf("%v: %v\n", i, FS)
	}
	for i, FS := range requester.session.FSBackward {
		log.Printf("%v: %v\n", i, FS)
	}

}

// BenchmarkSphinxRoundTrip3_2RelayNodeLevel benchmarks the set-up phase with a topology: Req->Rel2->Rel3->Rel4->Reso->Rel3->Rel2-Req
// calling functions manipulating the snet.Packet
func BenchmarkSphinxRoundTrip3_2RelayNodeLevel(b *testing.B) {
	for i := 0; i < b.N; i++ {
		requester, relay2, relay3, relay4, resolver := initRequesterRelayResolverForTestSphinx3_2Relay(b)

		pathingForward, pathingBackward := mocks.GetHardcodedHopByHopPath3_2Relay()

		// This is done 1 layer above
		// Globally the logic would be

		requesterPacket, keyToInitiateForwardFSPayload, err := requester.setupSphinxSession_createScionPacket()
		if err != nil {
			b.Fatalf("requester couldn't create the scion packet")
		}

		relay2Packet := &snet.Packet{}
		relay3Packet := &snet.Packet{}
		relay4Packet := &snet.Packet{}
		resolverAnswerPacket := &snet.Packet{}
		relay3AnswerPacket := &snet.Packet{}
		relay2AnswerPacket := &snet.Packet{}

		err = relay2.relayProcessSphinxSetup(requesterPacket, relay2Packet)
		if err != nil {
			b.Fatalf("Relay couldn't process the packet")
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingForward[1].Path, []byte("forw")), core.DataplanePathToBytes(relay2Packet.Path, []byte("forw"))) {
			b.Fatalf("Relay's not getting the correct routing info")
		}

		err = relay3.relayProcessSphinxSetup(*relay2Packet, relay3Packet)
		if err != nil {
			b.Fatalf("Relay couldn't process the packet")
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingForward[2].Path, []byte("forw")), core.DataplanePathToBytes(relay3Packet.Path, []byte("forw"))) {
			b.Fatalf("Relay's not getting the correct routing info")
		}

		err = relay4.relayProcessSphinxSetup(*relay3Packet, relay4Packet)
		if err != nil {
			b.Fatalf("Relay couldn't process the packet")
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingForward[3].Path, []byte("forw")), core.DataplanePathToBytes(relay4Packet.Path, []byte("forw"))) {
			b.Fatalf("Relay's not getting the correct routing info")
		}

		err = resolver.resolverProcessSphinxSetup(*relay4Packet, resolverAnswerPacket)
		if err != nil {
			b.Fatalf("Resolver couldn't process the packet")
		}

		resolverRawSphinxAnswerPacket := resolverAnswerPacket.Payload.(snet.UDPPayload).Payload
		resolverSphinxAnswerPacket := core.BytesToSetupPacket(resolverRawSphinxAnswerPacket)
		_ = resolverSphinxAnswerPacket.SphinxPayload
		_ = resolverSphinxAnswerPacket.FSPayload

		/*
			This check makes sense, but requires a change in API just for the test.
			I did it when refactoring, but not willing to clutter my code just to facilitate one check.
			resolverRawSphinxAnswerPacket := resolverAnswerPacket.Payload.(snet.UDPPayload).Payload
			resolverSphinxAnswerPacket := bytesToSetupPacket(resolverRawSphinxAnswerPacket)

			if !bytes.Equal(sphinxHeaderToBytes(resolverSphinxAnswerPacket.SphinxHDR), sphinxHeaderToBytes(SHDRb)) {
				b.Fatalf("SHDRb are not equal")
			}
		*/

		if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[0].Path, []byte("back")), core.DataplanePathToBytes(resolverAnswerPacket.Path, []byte("back"))) {
			b.Fatalf("Resolver's not getting the correct routing info")
		}

		err = relay3.relayProcessSphinxSetup(*resolverAnswerPacket, relay3AnswerPacket)
		if err != nil {
			b.Fatalf("Relay couldn't process the backward packet")
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[1].Path, []byte("back")), core.DataplanePathToBytes(relay3AnswerPacket.Path, []byte("back"))) {
			b.Fatalf("Relay's not getting the correct backward routing info")
		}

		err = relay2.relayProcessSphinxSetup(*relay3AnswerPacket, relay2AnswerPacket)
		if err != nil {
			b.Fatalf("Relay couldn't process the backward packet")
		}
		if !bytes.Equal(core.DataplanePathToBytes(pathingBackward[2].Path, []byte("back")), core.DataplanePathToBytes(relay2AnswerPacket.Path, []byte("back"))) {
			b.Fatalf("Relay's not getting the correct backward routing info")
		}

		err = requester.setupSphinxSession_processAnswerAndGetFSes(*relay2AnswerPacket, keyToInitiateForwardFSPayload)
		if err != nil {
			b.Fatalf("Requester couldn't process the answer")
		}
	}
}

// BenchmarkSphinxRoundTrip3_2RelayNodeLevelNoChecks benchmarks the set-up phase without checking for correctness (assumed to be done by previous tests) with a topology: Req->Rel2->Rel3->Rel4->Reso->Rel3->Rel2-Req
// There does not seem to be a statistically significant performance improvement by removing those couple of error checks.
func BenchmarkSphinxRoundTrip3_2RelayNodeLevelNoChecks(b *testing.B) {
	for i := 0; i < b.N; i++ {
		requester, relay2, relay3, relay4, resolver := initRequesterRelayResolverForTestSphinx3_2Relay(b)
		

		requesterPacket, keyToInitiateForwardFSPayload, _ := requester.setupSphinxSession_createScionPacket()

		relay2Packet := &snet.Packet{}
		relay3Packet := &snet.Packet{}
		relay4Packet := &snet.Packet{}
		resolverAnswerPacket := &snet.Packet{}
		relay3AnswerPacket := &snet.Packet{}
		relay2AnswerPacket := &snet.Packet{}

		relay2.relayProcessSphinxSetup(requesterPacket, relay2Packet)

		relay3.relayProcessSphinxSetup(*relay2Packet, relay3Packet)

		relay4.relayProcessSphinxSetup(*relay3Packet, relay4Packet)

		resolver.resolverProcessSphinxSetup(*relay4Packet, resolverAnswerPacket)

		resolverRawSphinxAnswerPacket := resolverAnswerPacket.Payload.(snet.UDPPayload).Payload
		resolverSphinxAnswerPacket := core.BytesToSetupPacket(resolverRawSphinxAnswerPacket)
		_ = resolverSphinxAnswerPacket.SphinxPayload
		_ = resolverSphinxAnswerPacket.FSPayload

		/*
			This check makes sense, but requires a change in API just for the test.
			I did it when refactoring, but not willing to clutter my code just to facilitate one check.
			resolverRawSphinxAnswerPacket := resolverAnswerPacket.Payload.(snet.UDPPayload).Payload
			resolverSphinxAnswerPacket := bytesToSetupPacket(resolverRawSphinxAnswerPacket)

			if !bytes.Equal(sphinxHeaderToBytes(resolverSphinxAnswerPacket.SphinxHDR), sphinxHeaderToBytes(SHDRb)) {
				b.Fatalf("SHDRb are not equal")
			}
		*/

		relay3.relayProcessSphinxSetup(*resolverAnswerPacket, relay3AnswerPacket)

		relay2.relayProcessSphinxSetup(*relay3AnswerPacket, relay2AnswerPacket)

		requester.setupSphinxSession_processAnswerAndGetFSes(*relay2AnswerPacket, keyToInitiateForwardFSPayload)

	}
}
