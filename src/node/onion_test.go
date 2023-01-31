package node

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/scionproto/scion/pkg/snet"
	"main.go/core"
	"main.go/crypto"
	"main.go/mocks"
	"testing"
)

// generateFSForSession1Relay generates 4 semi-random FSes for a topology with a single relay
func generateFSForSession1Relay(t *testing.T, session *Session, requesterSecretKey, relaySecretKey, resolverSecretKey []byte) {
	// GENERATE FSs
	decryptedFS0 := crypto.GenerateExampleFSWithRandomRouting(session.sharedKeysForward[0])
	//debugPrintDecryptedFS(decryptedFS0, "testCreation, relay FS")
	decryptedFS1 := crypto.GenerateExampleFSWithRandomRouting(session.sharedKeysForward[1])
	encryptedFS0, err := crypto.PRP(relaySecretKey, decryptedFS0)
	if err != nil {
		t.Fatalf("Couldn't encrypt the first FS, %v", err)
	}
	encryptedFS1, err := crypto.PRP(resolverSecretKey, decryptedFS1)
	if err != nil {
		t.Fatalf("Couldn't encrypt the second FS, %v", err)
	}
	FSForward := make([][]byte, 2)
	FSForward[0] = encryptedFS0
	FSForward[1] = encryptedFS1
	session.FSForward = FSForward

	// Backward FS, needed because CreateOnion use them.
	decryptedFS2 := crypto.GenerateExampleFSWithRandomRouting(session.sharedKeysBackward[0])
	decryptedFS3 := crypto.GenerateExampleFSWithRandomRouting(session.sharedKeysBackward[1])
	encryptedFS2, err := crypto.PRP(relaySecretKey, decryptedFS2)
	if err != nil {
		t.Fatalf("Couldn't encrypt the third FS, %v", err)
	}
	encryptedFS3, err := crypto.PRP(requesterSecretKey, decryptedFS3)
	if err != nil {
		t.Fatalf("Couldn't encrypt the fourth FS, %v", err)
	}
	FSBackward := make([][]byte, 2)
	FSBackward[0] = encryptedFS2
	FSBackward[1] = encryptedFS3
	session.FSBackward = FSBackward
}

// generateFSForSession3_2Relay generates 7 semi-random FSes for a topology: Req->Rel2->Rel3->Rel4->Reso->Rel3->Rel2-Req
func generateFSForSession3_2Relay(t testing.TB, session *Session, requesterSecretKey, relay2SecretKey, relay3SecretKey, relay4SecretKey, resolverSecretKey []byte) {
	// GENERATE FSs
	decryptedFS0 := crypto.GenerateExampleFSWithRandomRouting(session.sharedKeysForward[0])
	decryptedFS1 := crypto.GenerateExampleFSWithRandomRouting(session.sharedKeysForward[1])
	decryptedFS2 := crypto.GenerateExampleFSWithRandomRouting(session.sharedKeysForward[2])
	decryptedFS3 := crypto.GenerateExampleFSWithRandomRouting(session.sharedKeysForward[3])
	encryptedFS0, err := crypto.PRP(relay2SecretKey, decryptedFS0)
	if err != nil {
		t.Fatalf("Couldn't encrypt the first FS, %v", err)
	}
	encryptedFS1, err := crypto.PRP(relay3SecretKey, decryptedFS1)
	if err != nil {
		t.Fatalf("Couldn't encrypt the second FS, %v", err)
	}
	encryptedFS2, err := crypto.PRP(relay4SecretKey, decryptedFS2)
	if err != nil {
		t.Fatalf("Couldn't encrypt the 3 FS, %v", err)
	}
	encryptedFS3, err := crypto.PRP(resolverSecretKey, decryptedFS3)
	if err != nil {
		t.Fatalf("Couldn't encrypt the 4 FS, %v", err)
	}
	FSForward := make([][]byte, 4)
	FSForward[0] = encryptedFS0
	FSForward[1] = encryptedFS1
	FSForward[2] = encryptedFS2
	FSForward[3] = encryptedFS3
	session.FSForward = FSForward

	// Backward FS, needed because CreateOnion use them.
	decryptedFS0b := crypto.GenerateExampleFSWithRandomRouting(session.sharedKeysBackward[0])
	decryptedFS1b := crypto.GenerateExampleFSWithRandomRouting(session.sharedKeysBackward[1])
	decryptedFS2b := crypto.GenerateExampleFSWithRandomRouting(session.sharedKeysBackward[2])
	encryptedFS0b, err := crypto.PRP(relay3SecretKey, decryptedFS0b)
	if err != nil {
		t.Fatalf("Couldn't encrypt the 0b FS, %v", err)
	}
	encryptedFS1b, err := crypto.PRP(relay2SecretKey, decryptedFS1b)
	if err != nil {
		t.Fatalf("Couldn't encrypt the 1b FS, %v", err)
	}
	encryptedFS2b, err := crypto.PRP(requesterSecretKey, decryptedFS2b)
	if err != nil {
		t.Fatalf("Couldn't encrypt the 2b FS, %v", err)
	}
	FSBackward := make([][]byte, 3)
	FSBackward[0] = encryptedFS0b
	FSBackward[1] = encryptedFS1b
	FSBackward[2] = encryptedFS2b
	session.FSBackward = FSBackward
}

// TestCreateOnionToDecryption1RelaySoLength2 manipulates snet.Packet from the requester to the resolver with a single relay
func TestCreateOnionToDecryption1RelaySoLength2(t *testing.T) {
	dnsPayload := crypto.GenerateExampleDNSBytes()
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

	generateFSForSession1Relay(t, &session, resolver.secretKey, relay.secretKey, resolver.secretKey)

	// requester side
	packet, err := CreateOnion(dnsPayload, session)
	if err != nil {
		t.Fatalf("Couldn't generate the packet, %v", err)
	}
	//debugPrintPacket(packet, "after onion creation")

	initSizePayload := len(packet.Payload.(snet.UDPPayload).Payload)

	// relay side
	var nextPacket snet.Packet
	err = relay.relayProcessDataTypeForward(packet, &nextPacket)
	if err != nil {
		t.Fatalf("Couldn't process the packet at relay, %v", err)
	}

	//debugPrintPacket(packet, "after first relay")

	relaySizePayload := len(nextPacket.Payload.(snet.UDPPayload).Payload)

	if initSizePayload != relaySizePayload {
		t.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, relaySizePayload)
	}

	// resolver side
	// TODO ports are empty..
	nextPayload, _, _, err := resolver.removeLayer(nextPacket.Payload.(snet.UDPPayload).Payload, true)
	if err != nil {
		t.Fatalf("Couldn't decrypt the packet at resolver, %v", err)
	}

	// nextPayload size is not constant here, but that's fine at the payload is not forwarded further, this is because the padding has been removed.

	decryptedPayload := nextPayload[core.CHDRLength:]
	// AHDRf := decryptedPayload[:core.AHDRLength] // This is garbage randomness, as there's no more FS/next routing
	// AHDRb := decryptedPayload[core.AHDRLength : 2*core.AHDRLength]
	query := decryptedPayload[2*core.AHDRLength : len(decryptedPayload)-core.SecurityParameter]
	//IV0b := decryptedPayload[len(decryptedPayload)-SecurityParameter:]

	if !bytes.Equal(dnsPayload, query) {
		t.Errorf("Onioning didn't work properly")
		fmt.Println(dnsPayload)
		fmt.Println(query)
	}
}

// TestRoundTripValidity1Relay tests the data transmission phase and manipulates snet.Packet from the requester to the resolver and backward with a single relay
func TestRoundTripValidity1Relay(t *testing.T) {
	dnsPayload := crypto.GenerateExampleDNSBytes()
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
	requesterSecretKey := make([]byte, core.SecurityParameter)
	_, err = rand.Read(requesterSecretKey)
	if err != nil {
		t.Fatalf("Couldn't read randomness for the secretKey. Node not running, %v", err)
	}

	generateFSForSession1Relay(t, &session, requesterSecretKey, relay.secretKey, resolver.secretKey)

	requestNode := RequesterNode{
		node: Node{
			secretKey: requesterSecretKey,
		},
		sessionDuration: 1000,
		session:         session,
	}

	// requester side
	packet, err := CreateOnion(dnsPayload, session)
	if err != nil {
		t.Fatalf("Couldn't generate the packet, %v", err)
	}

	initiallyCreatedDataPacket := core.BytesToDataPacket(packet.Payload.(snet.UDPPayload).Payload)
	_ = initiallyCreatedDataPacket.DataPayload
	//debugPrintPacket(packet, "after onion creation")

	initSizePayload := len(packet.Payload.(snet.UDPPayload).Payload)

	// relay side
	var nextPacket snet.Packet
	err = relay.relayProcessDataTypeForward(packet, &nextPacket)
	if err != nil {
		t.Fatalf("Couldn't process the packet at relay, %v", err)
	}

	//debugPrintPacket(packet, "after first relay")
	relaySizePayload := len(nextPacket.Payload.(snet.UDPPayload).Payload)

	// the packet size should be constant
	if initSizePayload != relaySizePayload {
		t.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, relaySizePayload)
	}

	// resolver side
	// TODO ports are empty..
	nextPayload, _, sharedKey, err := resolver.removeLayer(nextPacket.Payload.(snet.UDPPayload).Payload, true)
	if err != nil {
		t.Fatalf("Couldn't decrypt the packet at resolver, %v", err)
	}

	decryptedPayload := nextPayload[core.CHDRLength:]
	// AHDRf := decryptedPayload[:core.AHDRLength] // This is garbage randomness, as there's no more FS/next routing
	AHDRb := decryptedPayload[core.AHDRLength : 2*core.AHDRLength]
	query := decryptedPayload[2*core.AHDRLength : len(decryptedPayload)-core.SecurityParameter]
	IV0b := decryptedPayload[len(decryptedPayload)-core.SecurityParameter:]

	if !bytes.Equal(dnsPayload, query) {
		fmt.Println(dnsPayload)
		fmt.Println(query)
		t.Fatalf("Onioning didn't work properly when decrypting query at resolver ")
	}
	// The if below includes testing for AHDRb and IV0b
	/*if !bytes.HasPrefix(initiallyCreatedOnion, decryptedPayload[core.AHDRLength:]) {
		fmt.Println(initiallyCreatedOnion)
		fmt.Println(decryptedPayload[core.AHDRLength:])
		t.Fatalf("Onioning didn't work properly when decrypting at resolver, including AHDR")
	}*/

	pureDNSpayload := []byte("success")
	// As per testHelpers.go prepareFakeSessionSymKeys comment, the symKey for the encryption as resolver == the symKey for the decryption
	O0b, err := crypto.ENC(sharedKey, IV0b, pureDNSpayload, core.DataPaddingFactor, true)

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

	var nextSCIONPacketFromResolver snet.Packet
	var nextSCIONPayloadFromResolver snet.UDPPayload
	nextSCIONPayloadFromResolver.Payload = payloadBack
	nextSCIONPacketFromResolver.Payload = nextSCIONPayloadFromResolver

	// relay side
	var nextPacketBack snet.Packet
	err = relay.relayProcessDataTypeBackward(nextSCIONPacketFromResolver, &nextPacketBack)
	if err != nil {
		t.Fatalf("Couldn't process the packet at relay, %v", err)
	}

	relaySizePayloadBackpath := len(nextPacketBack.Payload.(snet.UDPPayload).Payload)

	if initSizePayloadBackpath != relaySizePayloadBackpath {
		t.Fatalf("Payloads size not constant on the path back: %v vs %v", initSizePayloadBackpath, relaySizePayloadBackpath)
	}

	dnsAnswer, err := requestNode.onionDecrypt(nextPacketBack.Payload.(snet.UDPPayload).Payload)
	if err != nil {
		t.Fatalf("Couldn't decrypt the onion at requester")
	}

	if !bytes.Equal(dnsAnswer, []byte("success")) {
		fmt.Println(dnsAnswer)
		fmt.Println([]byte("success"))
		t.Fatalf("Onioning didn't work properly when decrypting at requester")
	}

}

// TestRoundTripValidity3_2Relay tests the data transmission phase with a topology: Req->Rel2->Rel3->Rel4->Reso->Rel3->Rel2-Req
func TestRoundTripValidity3_2Relay(t *testing.T) {
	dnsPayload := crypto.GenerateExampleDNSBytes()
	session := generateExampleSessionFromPathing(mocks.GetHardcodedHopByHopPath3_2Relay())

	relay2 := Node{}
	relay2.secretKey = make([]byte, core.SecurityParameter)
	_, err := rand.Read(relay2.secretKey)
	if err != nil {
		t.Fatalf("Couldn't read randomness for the secretKey. Node not running, %v", err)
	}
	relay3 := Node{}
	relay2.secretKey = make([]byte, core.SecurityParameter)
	_, err = rand.Read(relay3.secretKey)
	if err != nil {
		t.Fatalf("Couldn't read randomness for the secretKey. Node not running, %v", err)
	}
	relay4 := Node{}
	relay2.secretKey = make([]byte, core.SecurityParameter)
	_, err = rand.Read(relay4.secretKey)
	if err != nil {
		t.Fatalf("Couldn't read randomness for the secretKey. Node not running, %v", err)
	}
	resolver := Node{}
	resolver.secretKey = make([]byte, core.SecurityParameter)
	_, err = rand.Read(resolver.secretKey)
	if err != nil {
		t.Fatalf("Couldn't read randomness for the secretKey. Node not running, %v", err)
	}
	requesterSecretKey := make([]byte, core.SecurityParameter)
	_, err = rand.Read(requesterSecretKey)
	if err != nil {
		t.Fatalf("Couldn't read randomness for the secretKey. Node not running, %v", err)
	}

	generateFSForSession3_2Relay(t, &session, requesterSecretKey, relay2.secretKey, relay3.secretKey, relay4.secretKey, resolver.secretKey)

	requestNode := RequesterNode{
		node: Node{
			secretKey: requesterSecretKey,
		},
		sessionDuration: 1000,
		session:         session,
	}

	// requester side
	packet, err := CreateOnion(dnsPayload, session)
	if err != nil {
		t.Fatalf("Couldn't generate the packet, %v", err)
	}

	initiallyCreatedDataPacket := core.BytesToDataPacket(packet.Payload.(snet.UDPPayload).Payload)
	_ = initiallyCreatedDataPacket.DataPayload
	//debugPrintPacket(packet, "after onion creation")

	initSizePayload := len(packet.Payload.(snet.UDPPayload).Payload)

	// relay2 side
	var outPacketFRelay2 snet.Packet
	err = relay2.relayProcessDataTypeForward(packet, &outPacketFRelay2)
	if err != nil {
		t.Fatalf("Couldn't process the packet at relay, %v", err)
	}
	//debugPrintPacket(packet, "after first relay")
	relay2SizePayload := len(outPacketFRelay2.Payload.(snet.UDPPayload).Payload)
	// the packet size should be constant
	if initSizePayload != relay2SizePayload {
		t.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, relay2SizePayload)
	}

	// relay3 side
	var outPacketFRelay3 snet.Packet
	err = relay3.relayProcessDataTypeForward(outPacketFRelay2, &outPacketFRelay3)
	if err != nil {
		t.Fatalf("Couldn't process the packet at relay, %v", err)
	}
	relay3SizePayload := len(outPacketFRelay3.Payload.(snet.UDPPayload).Payload)
	// the packet size should be constant
	if initSizePayload != relay3SizePayload {
		t.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, relay3SizePayload)
	}

	// relay4 side
	var outPacketFRelay4 snet.Packet
	err = relay3.relayProcessDataTypeForward(outPacketFRelay3, &outPacketFRelay4)
	if err != nil {
		t.Fatalf("Couldn't process the packet at relay, %v", err)
	}
	relay4SizePayload := len(outPacketFRelay4.Payload.(snet.UDPPayload).Payload)
	// the packet size should be constant
	if initSizePayload != relay4SizePayload {
		t.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, relay4SizePayload)
	}

	// resolver side
	// TODO ports are empty..
	nextPayload, _, sharedKey, err := resolver.removeLayer(outPacketFRelay4.Payload.(snet.UDPPayload).Payload, true)
	if err != nil {
		t.Fatalf("Couldn't decrypt the packet at resolver, %v", err)
	}

	decryptedPayload := nextPayload[core.CHDRLength:]
	// AHDRf := decryptedPayload[:core.AHDRLength] // This is garbage randomness, as there's no more FS/next routing
	AHDRb := decryptedPayload[core.AHDRLength : 2*core.AHDRLength]
	query := decryptedPayload[2*core.AHDRLength : len(decryptedPayload)-core.SecurityParameter]
	IV0b := decryptedPayload[len(decryptedPayload)-core.SecurityParameter:]

	if !bytes.Equal(dnsPayload, query) {
		fmt.Println(dnsPayload)
		fmt.Println(query)
		t.Fatalf("Onioning didn't work properly when decrypting query at resolver ")
	}
	// The if below includes testing for AHDRb and IV0b
	/*if !bytes.HasPrefix(initiallyCreatedOnion, decryptedPayload[core.AHDRLength:]) {
		fmt.Println(initiallyCreatedOnion)
		fmt.Println(decryptedPayload[core.AHDRLength:])
		t.Fatalf("Onioning didn't work properly when decrypting at resolver, including AHDR")
	}*/

	pureDNSpayload := []byte("success")
	// As per prepareSessionSymKeys comment, the symKey for the encryption as resolver == the symKey for the decryption
	O0b, err := crypto.ENC(sharedKey, IV0b, pureDNSpayload, core.DataPaddingFactor, true)

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

	var nextSCIONPacketFromResolver snet.Packet
	var nextSCIONPayloadFromResolver snet.UDPPayload
	nextSCIONPayloadFromResolver.Payload = payloadBack
	nextSCIONPacketFromResolver.Payload = nextSCIONPayloadFromResolver

	// relay3 side
	var nextPacketBackRelay3 snet.Packet
	err = relay3.relayProcessDataTypeBackward(nextSCIONPacketFromResolver, &nextPacketBackRelay3)
	if err != nil {
		t.Fatalf("Couldn't process the packet at relay, %v", err)
	}
	relay3SizePayloadBackpath := len(nextPacketBackRelay3.Payload.(snet.UDPPayload).Payload)
	if initSizePayloadBackpath != relay3SizePayloadBackpath {
		t.Fatalf("Payloads size not constant on the path back: %v vs %v", initSizePayloadBackpath, relay3SizePayloadBackpath)
	}

	// relay2 side
	var nextPacketBackRelay2 snet.Packet
	err = relay2.relayProcessDataTypeBackward(nextPacketBackRelay3, &nextPacketBackRelay2)
	if err != nil {
		t.Fatalf("Couldn't process the packet at relay, %v", err)
	}
	relay2SizePayloadBackpath := len(nextPacketBackRelay2.Payload.(snet.UDPPayload).Payload)
	if initSizePayloadBackpath != relay2SizePayloadBackpath {
		t.Fatalf("Payloads size not constant on the path back: %v vs %v", initSizePayloadBackpath, relay2SizePayloadBackpath)
	}

	dnsAnswer, err := requestNode.onionDecrypt(nextPacketBackRelay2.Payload.(snet.UDPPayload).Payload)
	if err != nil {
		t.Fatalf("Couldn't decrypt the onion at requester")
	}

	if !bytes.Equal(dnsAnswer, []byte("success")) {
		fmt.Println(dnsAnswer)
		fmt.Println([]byte("success"))
		t.Fatalf("Onioning didn't work properly when decrypting at requester")
	}
}

// BenchmarkRoundTripValidity3_2Relay tests the data transmission phase with a topology: Req->Rel2->Rel3->Rel4->Reso->Rel3->Rel2-Req
func BenchmarkRoundTripValidity3_2Relay(b *testing.B) {
	for i := 0; i < b.N; i++ {
		dnsPayload := crypto.GenerateExampleDNSBytes()
		session := generateExampleSessionFromPathing(mocks.GetHardcodedHopByHopPath3_2Relay())

		relay2 := Node{}
		relay2.secretKey = make([]byte, core.SecurityParameter)
		_, err := rand.Read(relay2.secretKey)
		if err != nil {
			b.Fatalf("Couldn't read randomness for the secretKey. Node not running, %v", err)
		}
		relay3 := Node{}
		relay2.secretKey = make([]byte, core.SecurityParameter)
		_, err = rand.Read(relay3.secretKey)
		if err != nil {
			b.Fatalf("Couldn't read randomness for the secretKey. Node not running, %v", err)
		}
		relay4 := Node{}
		relay2.secretKey = make([]byte, core.SecurityParameter)
		_, err = rand.Read(relay4.secretKey)
		if err != nil {
			b.Fatalf("Couldn't read randomness for the secretKey. Node not running, %v", err)
		}
		resolver := Node{}
		resolver.secretKey = make([]byte, core.SecurityParameter)
		_, err = rand.Read(resolver.secretKey)
		if err != nil {
			b.Fatalf("Couldn't read randomness for the secretKey. Node not running, %v", err)
		}
		requesterSecretKey := make([]byte, core.SecurityParameter)
		_, err = rand.Read(requesterSecretKey)
		if err != nil {
			b.Fatalf("Couldn't read randomness for the secretKey. Node not running, %v", err)
		}

		generateFSForSession3_2Relay(b, &session, requesterSecretKey, relay2.secretKey, relay3.secretKey, relay4.secretKey, resolver.secretKey)

		requestNode := RequesterNode{
			node: Node{
				secretKey: requesterSecretKey,
			},
			sessionDuration: 1000,
			session:         session,
		}

		// requester side
		packet, err := CreateOnion(dnsPayload, session)
		if err != nil {
			b.Fatalf("Couldn't generate the packet, %v", err)
		}
		//initiallyCreatedIV, initiallyCreatedAHDR, initiallyCreatedFS, initiallyCreatedMac, initiallyCreatedBlinded, initiallyCreatedOnion := splitPacket(packet.Payload.(snet.UDPPayload).Payload)
		initiallyCreatedDataPacket := core.BytesToDataPacket(packet.Payload.(snet.UDPPayload).Payload)
		_ = initiallyCreatedDataPacket.DataPayload
		//debugPrintPacket(packet, "after onion creation")

		initSizePayload := len(packet.Payload.(snet.UDPPayload).Payload)

		// relay2 side
		var outPacketFRelay2 snet.Packet
		err = relay2.relayProcessDataTypeForward(packet, &outPacketFRelay2)
		if err != nil {
			b.Fatalf("Couldn't process the packet at relay, %v", err)
		}
		//debugPrintPacket(packet, "after first relay")
		relay2SizePayload := len(outPacketFRelay2.Payload.(snet.UDPPayload).Payload)
		// the packet size should be constant
		if initSizePayload != relay2SizePayload {
			b.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, relay2SizePayload)
		}

		// relay3 side
		var outPacketFRelay3 snet.Packet
		err = relay3.relayProcessDataTypeForward(outPacketFRelay2, &outPacketFRelay3)
		if err != nil {
			b.Fatalf("Couldn't process the packet at relay, %v", err)
		}
		relay3SizePayload := len(outPacketFRelay3.Payload.(snet.UDPPayload).Payload)
		// the packet size should be constant
		if initSizePayload != relay3SizePayload {
			b.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, relay3SizePayload)
		}

		// relay4 side
		var outPacketFRelay4 snet.Packet
		err = relay3.relayProcessDataTypeForward(outPacketFRelay3, &outPacketFRelay4)
		if err != nil {
			b.Fatalf("Couldn't process the packet at relay, %v", err)
		}
		relay4SizePayload := len(outPacketFRelay4.Payload.(snet.UDPPayload).Payload)
		// the packet size should be constant
		if initSizePayload != relay4SizePayload {
			b.Fatalf("Payloads size not constant: %v vs %v", initSizePayload, relay4SizePayload)
		}

		// resolver side
		// TODO ports are empty..
		nextPayload, _, sharedKey, err := resolver.removeLayer(outPacketFRelay4.Payload.(snet.UDPPayload).Payload, true)
		if err != nil {
			b.Fatalf("Couldn't decrypt the packet at resolver, %v", err)
		}

		decryptedPayload := nextPayload[core.CHDRLength:]
		// AHDRf := decryptedPayload[:core.AHDRLength] // This is garbage randomness, as there's no more FS/next routing
		AHDRb := decryptedPayload[core.AHDRLength : 2*core.AHDRLength]
		query := decryptedPayload[2*core.AHDRLength : len(decryptedPayload)-core.SecurityParameter]
		IV0b := decryptedPayload[len(decryptedPayload)-core.SecurityParameter:]

		if !bytes.Equal(dnsPayload, query) {
			fmt.Println(dnsPayload)
			fmt.Println(query)
			b.Fatalf("Onioning didn't work properly when decrypting query at resolver ")
		}
		// The if below includes testing for AHDRb and IV0b
		/*if !bytes.HasPrefix(initiallyCreatedOnion, decryptedPayload[core.AHDRLength:]) {
			fmt.Println(initiallyCreatedOnion)
			fmt.Println(decryptedPayload[core.AHDRLength:])
			b.Fatalf("Onioning didn't work properly when decrypting at resolver, including AHDR")
		}*/

		pureDNSpayload := []byte("success")
		// As per testHelpers.go prepareFakeSessionSymKeys comment, the symKey for the encryption as resolver == the symKey for the decryption
		O0b, err := crypto.ENC(sharedKey, IV0b, pureDNSpayload, core.DataPaddingFactor, true)

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

		var nextSCIONPacketFromResolver snet.Packet
		var nextSCIONPayloadFromResolver snet.UDPPayload
		nextSCIONPayloadFromResolver.Payload = payloadBack
		nextSCIONPacketFromResolver.Payload = nextSCIONPayloadFromResolver

		// relay3 side
		var nextPacketBackRelay3 snet.Packet
		err = relay3.relayProcessDataTypeBackward(nextSCIONPacketFromResolver, &nextPacketBackRelay3)
		if err != nil {
			b.Fatalf("Couldn't process the packet at relay, %v", err)
		}
		relay3SizePayloadBackpath := len(nextPacketBackRelay3.Payload.(snet.UDPPayload).Payload)
		if initSizePayloadBackpath != relay3SizePayloadBackpath {
			b.Fatalf("Payloads size not constant on the path back: %v vs %v", initSizePayloadBackpath, relay3SizePayloadBackpath)
		}

		// relay2 side
		var nextPacketBackRelay2 snet.Packet
		err = relay2.relayProcessDataTypeBackward(nextPacketBackRelay3, &nextPacketBackRelay2)
		if err != nil {
			b.Fatalf("Couldn't process the packet at relay, %v", err)
		}
		relay2SizePayloadBackpath := len(nextPacketBackRelay2.Payload.(snet.UDPPayload).Payload)
		if initSizePayloadBackpath != relay2SizePayloadBackpath {
			b.Fatalf("Payloads size not constant on the path back: %v vs %v", initSizePayloadBackpath, relay2SizePayloadBackpath)
		}

		dnsAnswer, err := requestNode.onionDecrypt(nextPacketBackRelay2.Payload.(snet.UDPPayload).Payload)
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
