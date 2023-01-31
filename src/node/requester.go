package node

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/miekg/dns"
	"github.com/scionproto/scion/pkg/snet"
	"log"
	"main.go/core"
	crypto2 "main.go/crypto"
	"main.go/go-sphinxmixcrypto"
	"main.go/mocks"
	"os"
	"strings"
	"time"
)

// RunRequesterNode should run awaiting user input in the CLI
// Parameters will include the actual number of relays on the way forward path,
// the actual number of relays on the backward path, the max number of relays, whether the OR is activated or not.
// In a real-life SCION-like setting (path aware), the actual number of relays would not be explicitly specified.
// Instead, the forward path and the backward path to and from the recursive resolver would be given.
// And those might even only be given within the node CLI.
// Valid commands should be
// help or h to display the valid commands
// exit or q or quit to terminate the application
// resolve or r or dig [domain] to make a query
// Precise timing logging should be enabled, and all values should be printed at the end of a query.
// Inspiration taken from https://github.com/miekg/exdns/blob/master/q/q.go
// But adapted to SCION and my coding style, and added onion capabilities
func RunRequesterNode(onioning bool, localAddr snet.SCIONAddress, recursiveResolverAddress snet.SCIONAddress, sciondAddr string, dispatcherSocket string) {

	rNode := RequesterNode{}
	rNode.node = initNode(mocks.DefaultResolverKeyStateHardcoded())
	rNode.node.onioning = onioning // from CLI args

	rNode.node.CreateScionPacketConn(localAddr, nil, sciondAddr, dispatcherSocket)

	// I reuse the PacketInfo struct for the pathing but keeping the payloads empty here
	pathingForward, pathingBackward := rNode.node.getHopByHopPaths(localAddr, recursiveResolverAddress)
	rNode.session.pathingForward = pathingForward
	rNode.session.pathingBackward = pathingBackward

	if !rNode.session.startTime.IsZero() {
		log.Println("Init startTime properly!!")
	}
	rNode.sessionDuration = time.Duration(core.SessionDurationSeconds) * time.Second

	randReader, err := mocks.NewChachaEntropyReader(mocks.HardcodedChachaEntropyKeyStr)
	if err != nil {
		log.Println("Can't get a ChachaEntropyReader")
	}
	// TODO PKI must be a map from "address" (node routing information) to their asymPublicKey. Assumed by HORNET to be already known so I hardcode it here.
	rNode.sphinxHeaderFactory = sphinxmixcrypto.NewMixHeaderFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded(), randReader)
	rNode.sphinxPacketFactory = sphinxmixcrypto.NewSphinxPacketFactory(core.DefaultSphinxParams(), mocks.DefaultPKIHardcoded(), randReader)

	fmt.Println("This is a requester node (stub resolver), " +
		"please enter your command or help for a list of valid commands")

	for {
		input, err := bufio.NewReader(os.Stdin).ReadString('\n')
		input = strings.TrimSuffix(input, "\n")
		if err != nil {
			log.Println(err)
			log.Println("Scanning failed")
			return
		}
		if strings.EqualFold(input, "help") || strings.EqualFold(input, "h") {
			fmt.Println("Valid commands should be:")
			fmt.Println("help or h to display the valid commands")
			fmt.Println("exit or q or quit to terminate the application")
			fmt.Println("resolve or r or dig [domain] to make a query")
		} else if strings.EqualFold(input, "exit") || strings.EqualFold(input, "quit") || strings.EqualFold(input,
			"q") {
			fmt.Println("Resolver node shutting down")
			// TODO could wait awhile to handle answers, not necessary.
			os.Exit(0)
		} else if strings.HasPrefix(input, "dig ") || strings.HasPrefix(input,
			"resolve ") || strings.HasPrefix(input, "r ") {
			domain := strings.Split(input, " ")[1]
			if _, ok := dns.IsDomainName(domain); !ok {
				fmt.Println("Invalid domain name")
				continue
			}
			rNode.ResolveQuery(domain)
		} else {
			fmt.Println("Unknown input, type help to display the valid commands")
		}
	}
}

// ResolveQuery is inspired by https://github.com/miekg/exdns/blob/master/q/q.go
// But adapted to SCION and my coding style, and added onion capabilities
func (n *RequesterNode) ResolveQuery(domain string) {

	qname := domain
	qtype := dns.TypeA
	qclass := dns.ClassINET

	// I strongly believe I can't rely on dns.Client because of SCION. So I can only use dns package to create the msg, not to send the packet and instantly resolve the query.

	dnsParams := core.DefaultDNSParameters()
	m := createDNSMessage(dnsParams)
	m.Question[0] = dns.Question{Name: dns.Fqdn(qname), Qtype: qtype, Qclass: uint16(qclass)}
	m.Id = dns.Id()

	fmt.Printf("%s", m.String())
	fmt.Printf("\n;; size: %d bytes\n\n", m.Len())

	pureDNSpayload, err := m.Pack()
	if err != nil {
		log.Println(err)
		return
	}

	var packet snet.Packet
	startTimeMetric := time.Now()

	if n.node.onioning {
		if isSessionExpired(n.session.startTime, n.sessionDuration) {
			// Create a new session with sphinx and block
			// Copy the values of the pathing and the pubkey of the other nodes
			// The whole session must not be reset as the asym keys and the pathing is kept
			err = n.initSessionLocally()
			if err != nil {
				log.Println("Couldn't init the sphinx session locally")
				return
			}
			err = n.setupSphinxSession()
			if err != nil {
				log.Println("Couldn't setup the sphinx session with the other nodes")
				return
			}
		}
		packet, err = CreateOnion(pureDNSpayload, n.session)
		if err != nil {
			fmt.Println("Onion creation unsuccessful")
			return
		}

	} else {
		packet, err = mocks.CreatePacket(pureDNSpayload, n.session.pathingForward)
		if err != nil {
			fmt.Println("Non-onioned packet creation unsuccessful")
			return
		}
	}
	err = n.node.Send(packet)
	if err != nil {
		log.Println(err)
		return
	}

	// listenDataAtRequester will block until the reply reaches or until after a set-delay
	go n.listenDataAtRequester(startTimeMetric)
}

// initSessionLocally takes care of checking path validity and attribute the starting time of the session.
func (n *RequesterNode) initSessionLocally() error {
	if len(n.session.pathingForward) > int(core.MaxPathLength) || len(n.session.pathingBackward) > int(core.MaxPathLength) {
		err := errors.New("pathing is too long for current implementation")
		log.Println(err)
		return err
	}

	n.session.startTime = time.Now()
	return nil
}

// setupSphinxSession the paths and the public keys of the nodes in the paths are already fetched and stored in session.
// setupSphinxSession is blocking! The logic behind it is that when a DNS request is made, a session must exist. If not,
// it must be created. Once it's created, the DNS request must still be made.
// Note that this is adapted to the dig-like behaviour. In a real browser implementation, while the overall logic is the same
// further DNS requests should still be able to be added to the queue while the session is in creation.
// I modulate it into 3 sub-functions for readability.
func (n *RequesterNode) setupSphinxSession() error {
	scionPacket, keyToInitiateForwardFSPayload, err := n.setupSphinxSession_createScionPacket()
	if err != nil {
		log.Println("Requester couldn't create the scion packet necessary to setup the sphinx session")
		return err
	}

	answerScionPacket, err := n.setupSphinxSession_sendBlockAndListen(scionPacket)
	if err != nil {
		log.Println("Requester failed to send or receive the sphinx packet")
		return err
	}

	err = n.setupSphinxSession_processAnswerAndGetFSes(answerScionPacket, keyToInitiateForwardFSPayload)
	if err != nil {
		log.Println("Requester failed to process the sphinx answer and retrieve the FSes")
		return err
	}

	return nil
}

// setupSphinxSession_processAnswerAndGetFSes could either choose to add its own useless FS for systematisation, or not.
// I choose to do so as it avoids some issues.
// It is a sub-function of setupSphinxSession
func (n *RequesterNode) setupSphinxSession_processAnswerAndGetFSes(answerScionPacket snet.Packet, keyToInitiateForwardFSPayload []byte) error {
	rawAnswerPacket := answerScionPacket.Payload.(snet.UDPPayload).Payload

	if rawAnswerPacket[0] != core.SetupType {
		err := errors.New("first packet received is not for the sphinx setup")
		log.Println(err)
		return err
	}

	answerPacket := core.BytesToSetupPacket(rawAnswerPacket)

	FSPayloadForward, err := n.unwrapSphinxPayloadAtSource(n.session.sharedKeysForward[len(n.session.sharedKeysForward)-1], n.session.sharedKeysBackward, answerPacket.SphinxPayload)
	if err != nil {
		log.Println("Couldn't unwrap the sphinx payload at source")
		return err
	}

	// While FSes carry the 16bytes key by necessity, they are currently added to the payload with the 16bytes key
	// see processSphinxSetup. So need to cut down the keys before retrieving the FSes
	// But after unwrapping, as the "wrapping" was done by relays using the 32bytes key.
	n.session.CutDownAllSymKeys()

	// Add a own useless FS for consistency.
	localSharedKey16 := n.session.sharedKeysBackward[len(n.session.sharedKeysBackward)-1]
	decryptedFS := core.DecryptedFS{
		Routing:   make([]byte, 8),
		EXP:       core.BytesEXPToFSExpField(answerPacket.CHDR.IVorEXP),
		SharedKey: localSharedKey16,
	}
	encryptedFS, err := encryptFS(n.node.secretKey, decryptedFS)
	if err != nil {
		log.Println("Couldn't encrypt own FS before adding it")
		return err
	}
	finalBackwardFSPayload, err := addFStoPayload(localSharedKey16, encryptedFS, answerPacket.FSPayload)
	if err != nil {
		log.Println("Couldn't add the FS to the payload")
		return err
	}

	n.session.FSForward, err = retrieveFSes(keyToInitiateForwardFSPayload, n.session.sharedKeysForward, FSPayloadForward)
	if err != nil {
		log.Println("Couldn't retrieve the forward FSes")
		return err
	}
	// Use the resolver sharedKey as the init of the FS payload
	n.session.FSBackward, err = retrieveFSes(n.session.sharedKeysForward[len(n.session.sharedKeysForward)-1], n.session.sharedKeysBackward, finalBackwardFSPayload)
	if err != nil {
		log.Println("Couldn't retrieve the backward FSes")
		return err
	}
	return nil
}

// setupSphinxSession_sendBlockAndListen is blocking and returns the decoded scion response packet containing the FSes.
// It is a sub-function of setupSphinxSession
func (n *RequesterNode) setupSphinxSession_sendBlockAndListen(scionPacket snet.Packet) (snet.Packet, error) {
	err := n.node.Send(scionPacket)
	if err != nil {
		log.Println(err)
		log.Println("Requester couldn't send the SetupPacket")
		return snet.Packet{}, err
	}

	// As described in the doc, listening for the answer is blocking and this is fine.
	answerScionPacket, err := n.node.Listen()
	if err != nil {
		log.Println("Requester couldn't listen to the SetupPacket answer")
		return snet.Packet{}, err
	}

	// TODO UDP ports? on the snet.UDPPayload

	return answerScionPacket, nil
}

// setupSphinxSession_createScionPacket returns a scion sphinx setup packet, followed by the random key used to initiate the FS payload. (which is necessary to retrieve the FSes from the response)
// It is a sub-function of setupSphinxSession
func (n *RequesterNode) setupSphinxSession_createScionPacket() (snet.Packet, []byte, error) {
	if len(n.session.pathingForward) == 0 || len(n.session.pathingBackward) == 0 {
		err := errors.New("the paths for the session are not defined")
		log.Println(err)
		return snet.Packet{}, nil, err
	}

	CHDR := core.CHDR{
		Type:    core.SetupType,
		Hops:    core.MaxPathLength,
		IVorEXP: core.DurationToEXPBytes(n.sessionDuration),
	}

	SHDRf, SHDRb, err, sharedSecretsForward32bytes := n.generateSphinxHeaders(&n.session, CHDR)
	if err != nil {
		log.Println("Couldn't generate the sphinx headers")
		return snet.Packet{}, nil, err
	}

	sphinxPayload, err := n.generateSphinxPayloadForward(sharedSecretsForward32bytes, SHDRf, SHDRb)
	if err != nil {
		log.Println("Couldn't generate the SphinxPayloadForward")
		return snet.Packet{}, nil, err
	}

	keyToInitiateForwardFSPayload := make([]byte, core.SecurityParameter)
	bytesAmount, err := rand.Read(keyToInitiateForwardFSPayload)
	if err != nil || bytesAmount != core.SecurityParameter {
		log.Println("Error while generating random SymKeys")
		log.Println(err)
		return snet.Packet{}, nil, err
	}
	FSPayload, err := crypto2.PRG(keyToInitiateForwardFSPayload)
	if err != nil {
		log.Println("Couldn't initiate the FSPayload")
		return snet.Packet{}, nil, err
	}

	setupPacket := core.SetupPacket{
		CHDR:          CHDR,
		SphinxHDR:     SHDRf,
		SphinxPayload: sphinxPayload,
		FSPayload:     FSPayload,
	}

	rawSetupPacket := core.SetupPacketToBytes(setupPacket)

	UDPPayload := snet.UDPPayload{
		SrcPort: 04104, // TODO
		DstPort: 04104, // TODO
		Payload: rawSetupPacket,
	}

	scionPacket := snet.Packet{
		Bytes: nil,
		PacketInfo: snet.PacketInfo{
			Destination: n.session.pathingForward[0].Destination,
			Source:      n.session.pathingForward[0].Source,
			Path:        n.session.pathingForward[0].Path,
			Payload:     UDPPayload,
		},
	}
	return scionPacket, keyToInitiateForwardFSPayload, nil
}

// CreateOnion prepares a packet for the data-transmission phase.
// It assumes a Session has already been established through Sphinx!
func CreateOnion(dnsPayload []byte, session Session) (snet.Packet, error) {
	var packet snet.Packet
	packet.Source = session.pathingForward[0].Source
	packet.Destination = session.pathingForward[0].Destination
	packet.Path = session.pathingForward[0].Path
	var payload snet.UDPPayload
	payload.SrcPort = 04104 // TODO
	payload.DstPort = 04104 // TODO

	IV0f := make([]byte, core.SecurityParameter)
	IV0b := make([]byte, core.SecurityParameter)
	_, err := rand.Read(IV0f)
	if err != nil {
		log.Println("Couldn't read randomness for IV")
		return snet.Packet{}, err
	}
	_, err = rand.Read(IV0b)
	if err != nil {
		log.Println("Couldn't read randomness for IV")
		return snet.Packet{}, err
	}

	CHDRf := core.CHDR{
		Type:    core.DataTypeForward,
		Hops:    core.MaxPathLength,
		IVorEXP: IV0f,
	}

	IVsf, blindedl1f, err := PrepareIVandPadding(IV0f, session.sharedKeysForward, uint8(len(session.pathingForward)))
	if err != nil {
		log.Println("Couldn't prepare the forward IV and padding")
		return snet.Packet{}, err
	}
	IVsb, blindedl1b, err := PrepareIVandPadding(IV0b, session.sharedKeysBackward, uint8(len(session.pathingBackward)))
	if err != nil {
		log.Println("Couldn't prepare the backward IV and padding")
		return snet.Packet{}, err
	}

	mac0b, blinded0b, err := PrepareHeaderBackward(IVsb, session.sharedKeysBackward, session.FSBackward, blindedl1b, uint8(len(session.pathingBackward)))
	if err != nil {
		log.Println("Couldn't prepare backward header")
		return snet.Packet{}, err
	}
	ahdrb := append(session.FSBackward[0], mac0b...)
	ahdrb = append(ahdrb, blinded0b...)

	decryptedOnionf := append(ahdrb, dnsPayload...)
	decryptedOnionf = append(decryptedOnionf, IV0b...)
	mac0f, blinded0f, dataPayload0f, err := OnionEncryptForward(IVsf, session.sharedKeysForward, session.FSForward, blindedl1f, uint8(len(session.pathingForward)), decryptedOnionf)
	if err != nil {
		log.Println("Couldn't prepare forward onion")
		return snet.Packet{}, err
	}

	AHDRf := core.AHDR{
		FS:      session.FSForward[0],
		Mac:     mac0f,
		Blinded: blinded0f,
	}

	dataPacket := core.DataPacket{
		CHDR:        CHDRf,
		AHDR:        AHDRf,
		DataPayload: dataPayload0f,
	}

	payload.Payload = core.DataPacketToBytes(dataPacket)

	packet.Payload = payload
	return packet, nil
}

// PrepareIVandPadding is the first loop of the create_onion routine. It pre-computes all the mutations of the IV for each hop
// as well as prepare a byte slice cleverly so that FS can constantly be retrieved from it even while keeping a fixed packet length.
func PrepareIVandPadding(InitialIV []byte, sharedSymKeys [][]byte, l uint8) (IVs [][]byte, blindedl1 []byte, err error) {
	block0s := make([]byte, core.BlockLength)
	phi := make([]byte, 0)
	IVs = make([][]byte, l)
	IVs[0] = InitialIV

	var i uint8
	for i = 1; i < l; i++ {
		IVs[i], err = crypto2.PRP(sharedSymKeys[i-1], IVs[i-1]) // I think it's s_i-1 here as the first (index0) sharedSymKeys is for node 1
		if err != nil {
			log.Println("Couldn't mutate the IV")
			return nil, nil, err
		}
		paddedPhi := append(phi, block0s...)
		// PRG might want to first hash the value, then create some randomness. So do I use the hash as a seed of rand? That sounds about right
		// here I deviate from TARANET algo to append instead of xor. Seem more logical to me (or xor everywhere otherwise).
		randomness, err := crypto2.PRG(append(sharedSymKeys[i-1], IVs[i-1]...))
		if err != nil {
			log.Println("Couldn't generate static randomness")
			return nil, nil, err
		}
		phi, err = xor(paddedPhi, randomness[int(core.MaxPathLength-i)*core.BlockLength:]) // see note in ppt Design Pitch last slide
		if err != nil {
			log.Println("Couldn't xor paddedPhi with randomness")
			return nil, nil, err
		}
	}

	garbageRand := make([]byte, (int(core.MaxPathLength-l))*core.BlockLength)
	_, err = rand.Read(garbageRand)
	if err != nil {
		log.Println("Couldn't read randomness for garbageRand")
		return nil, nil, err
	}

	blindedl1 = append(garbageRand, phi...)
	return IVs, blindedl1, nil
}

// PrepareHeaderBackward is the second loop of my create_onion routine. Akin to HORNET, it prepares the header for the recursive resolver
// to use, so that the recursive resolver stays unaware of the path.
// It is very similar to OnionEncryptForward, except that OnionEncryptForward also take care of the onion encryption.
// Keeping them separate instead of refactoring with checks on onion != nil to split the cases is worse for maintainability of the code
// But is better for clarity and explicit naming.
func PrepareHeaderBackward(IVs [][]byte, sharedSymKeys [][]byte, FSs [][]byte, blindedl1 []byte, l uint8) ([]byte, []byte, error) {
	mac := crypto2.MAC(sharedSymKeys[l-1], IVs[l-1], FSs[l-1], blindedl1, nil)
	blinded := blindedl1
	var err error

	var i int
	for i = int(l) - 2; i >= 0; i-- {
		blinded, err = blind(FSs[i+1], mac, blinded, sharedSymKeys[i], IVs[i])
		if err != nil {
			log.Printf("Couldn't blind the FS at iteration %v\n", i)
			return nil, nil, err
		}

		mac = crypto2.MAC(sharedSymKeys[i], IVs[i], FSs[i], blinded, nil)
	}

	return mac, blinded, nil
}

// OnionEncryptForward is the third loop of my create_onion routine. Akin to TARANET, it prepares the header and the onion-encryption
// for the forward path.
// It is very similar to PrepareHeaderBackward, except that PrepareHeaderBackward does not take care of the onion encryption.
// Keeping them separate instead of refactoring with checks on onion != nil to split the cases is worse for maintainability of the code
// But is better for clarity and explicit naming.
func OnionEncryptForward(IVs [][]byte, sharedSymKeys [][]byte, FSs [][]byte, blindedl1 []byte, l uint8, decryptedPayload []byte) ([]byte, []byte, []byte, error) {
	onion, err := crypto2.ENC(sharedSymKeys[l-1], IVs[l-1], decryptedPayload, core.DataPaddingFactor, true)
	if err != nil {
		log.Println("Couldn't encrypt the onion for the forward path")
		return nil, nil, nil, err
	}
	mac := crypto2.MAC(sharedSymKeys[l-1], IVs[l-1], FSs[l-1], blindedl1, onion)
	blinded := blindedl1

	var i int
	for i = int(l) - 2; i >= 0; i-- {
		blinded, err = blind(FSs[i+1], mac, blinded, sharedSymKeys[i], IVs[i])
		if err != nil {
			log.Printf("Couldn't blind the FS at iteration %v\n", i)
			return nil, nil, nil, err
		}

		onion, err = crypto2.ENC(sharedSymKeys[i], IVs[i], onion, core.DataPaddingFactor, false)
		if err != nil {
			log.Println("Couldn't encrypt the onion for the forward path")
			return nil, nil, nil, err
		}

		mac = crypto2.MAC(sharedSymKeys[i], IVs[i], FSs[i], blinded, onion)
	}

	return mac, blinded, onion, nil
}



// listenDataAtRequester waits for the DNS response snet.Packet and gives the order to process it. Then prints some statistics.
// It will block until the reply reaches or until after a set-delay
func (n *RequesterNode) listenDataAtRequester(startTime time.Time) {
	packet, err := n.node.Listen()
	if err != nil {
		log.Println(err)
		return
	}

	var pld gopacket.Payload

	if n.node.onioning {
		pld, err = n.onionDecrypt(packet.Payload.(snet.UDPPayload).Payload)
		if err != nil {
			log.Println("Couldn't decrypt the onion at requester")
			return
		}
	}

	reply := new(dns.Msg)
	if err = reply.Unpack(pld); err != nil {
		log.Println(err)
		return
	}

	rtt := time.Since(startTime)
	fmt.Println("Times and packet sizes")
	fmt.Printf("RTT: %v\n", rtt)

	fmt.Printf("%v", reply)
	fmt.Printf("\n;; query time: %.3d µs, size: %d bytes\n", rtt/1e3, reply.Len())
}

// createDNSMessage prepares the shell of a *dns.Msg by using the params passed in argument.
// The actual message must be added later.
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

// onionDecrypt processes the answered onion by removing all its layers and return the raw (byte slice) decrypted DNS response
func (n *RequesterNode) onionDecrypt(rawDataPacket []byte) ([]byte, error) {
	dataPacket := core.BytesToDataPacket(rawDataPacket)

	// Check MAC once only. If the final MAC is correct, then no need to check the intermediary MACs
	// And with that, no need to mutate the FS/Blinded each step.
	/* Or do I?
	There is an asymmetry in my usage of the path. Let's take the example of source-relay-dest
	On the forward, the source knows the routing information, and the dest doesn't "need it",
	so only 1 FS is needed for routing and integrity for the relay
	and 1 FS for integrity for the destination
	On the backward path, the destination needs 1 FS for the routing (and check integrity by default)
	The relay needs 1 FS for routing+integrity
	And the source needs to check the integrity.
	So Option 1) Accept the asymmetry and add an extra FS with garbage routing just for the MAC on the way back
	Option 2) Source could not check MAC (bad), or could check intermediate MAC (potentially bad)
	Option 3) Include the first backrouting in the last forward FS. Then have dest behaving as source.
	I like option 3, but then I need to go back to dest having a single shared key for back and forth
	And I'd need to adapt the FSes key adequately (FSbackward[0] should include the key for the relay, while
	the last FS of FSbackward would include a sharedKey for the source so that the source can check the MAC)
	With option 3, the "invariants" become if you receive a packet, the packet includes an FS.
	The FS included MAC and EXP for the integrity and the routing information to send the packet.
	The dest routing information is the information to send post-resolving
	The source routing information is garbage and can be discarded. i.e. (noting that the path is not necessarily symmetric:
	S->R1->D->R2->S implies R1 gets FSf[0], D gets FSf[1], R2 gets FSb[0] and S gets FSb[1].)
	*/

	decryptedFS, err := decryptAndCheckFS(n.node.secretKey, dataPacket.AHDR.FS)
	if err != nil {
		log.Println("Error while decrypting the FS")
		return nil, err
	}

	// For some reason (GC?), calling MAC, change my local MacValue. So I'm using this trick to force a valid comparison.
	macReceivedCopy := make([]byte, len(dataPacket.AHDR.Mac))
	copy(macReceivedCopy, dataPacket.AHDR.Mac)

	macComputed := crypto2.MAC(decryptedFS.SharedKey, dataPacket.CHDR.IVorEXP, dataPacket.AHDR.FS, dataPacket.AHDR.Blinded, nil)
	if !hmac.Equal(macComputed, macReceivedCopy) {
		err = errors.New("providedMac does not match computedMac")
		log.Println(err)
		return nil, err
	}

	IV := dataPacket.CHDR.IVorEXP
	Onion := dataPacket.DataPayload

	// -2 as the one at index l-1 is the local one use for the MAC above
	// However, must do one last decryption with the last key of the forward session.
	for i := len(n.session.sharedKeysBackward) - 2; i >= 0; i-- {
		sharedKey := n.session.sharedKeysBackward[i]

		// should be checking the MAC here as well? Don't think it's needed as the first mac check should encompass everything

		// mutateIV
		IV, err = crypto2.PRPInverse(sharedKey, IV)
		if err != nil {
			log.Println(err)
			log.Println("issue when mutating the IV in reverse")
			return nil, err
		}

		// remove1Layer
		Onion, err = crypto2.DEC(sharedKey, IV, Onion, false)
		if err != nil {
			log.Println(err)
			log.Println("issue when removing an onion layer")
			return nil, err
		}
	}

	// shouldn't I have 1 more IV mutation here? But the test passes. Am I missing the mutation at the resolver?
	// Might not be crucial. As I'm having the resolver behaving like the requester (FS-wise), the IV0 is known by the resolver
	// but is meant for the first relay

	decryptedDNSAnswer, err := crypto2.DEC(n.session.sharedKeysForward[len(n.session.sharedKeysForward)-1], IV, Onion, true)
	if err != nil {
		log.Println(err)
		log.Println("issue when removing an onion layer")
		return nil, err
	}

	return decryptedDNSAnswer, nil
}
