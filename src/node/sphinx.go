package node

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"log"
	"main.go/core"
	"main.go/crypto"
	"main.go/go-sphinxmixcrypto"
	"main.go/mocks"
)

// As Sphinx needs to access Node type, it s sense to have sphinx.go in the node pkg similar to onion
// And in the crypto pkg a file called asym crypto taking care of only the crypto wrapper. => not needed since I use external code for sphinx who took care themselves of the asym crypto

const SphinxRouteLength = 16

// processSphinxSetup processes the SetupPacket type of the sphinx phase. It is used by both relay and resolver and is
// akin to removeLayer conceptually. It is different from relayProcessSphinxSetup (which is one level higher, manipulating
// snet.Packet) and from processSphinxPacket which corresponds to HORNET PROC_SPHX_PKT.
func (n *Node) processSphinxSetup(setupPacket core.SetupPacket, nextSetupPacket *core.SetupPacket) (sharedKey32, routing []byte, err error) {
	nextSphinxHeader, nextSphinxPayload, sharedKey32, routing, err := n.processSphinxPacket(setupPacket.SphinxHDR, setupPacket.SphinxPayload)
	if err != nil {
		log.Println("Couldn't processSphinxPacket")
		return nil, nil, err
	}

	sharedKey16 := cutDownSymKey(sharedKey32)

	if isEXPExpired(setupPacket.CHDR.IVorEXP) {
		err = fmt.Errorf("session expired, packet dropped")
		log.Println(err)
		return nil, nil, err
	}

	decryptedFS := core.DecryptedFS{
		Routing:   routing,
		EXP:       core.BytesEXPToFSExpField(setupPacket.CHDR.IVorEXP),
		SharedKey: sharedKey16,
	}


	encryptedFS, err := encryptFS(n.secretKey, decryptedFS)
	if err != nil {
		log.Println("Couldn't encrypt own FS before adding it")
		return nil, nil, err
	}

	nextFSPayload, err := addFStoPayload(sharedKey16, encryptedFS, setupPacket.FSPayload)
	if err != nil {
		log.Println("Couldn't add the FS to the payload")
		return nil, nil, err
	}

	// DEST NEEDS TO GET as output the sharedKey, the sphinx payload and the FS payload.
	// The FS payload must be the nextFSPayload.
	// It sounds reasonable to also assume that the sphinxPayload must be the nextSphinxPayload.
	// So that the payload is correctly encrypted by one last layer prior to reaching the destination.

	nextSetupPacket.CHDR = setupPacket.CHDR
	nextSetupPacket.SphinxHDR = nextSphinxHeader
	nextSetupPacket.SphinxPayload = nextSphinxPayload
	nextSetupPacket.FSPayload = nextFSPayload

	return sharedKey32, routing, nil
}

// addFStoPayload corresponds to Algo 1 from HORNET
func addFStoPayload(sharedKey16 []byte, FS []byte, FSPayload core.FSPayload) (core.FSPayload, error) {
	log.Println(FS)
	// TODO comment print above when not testing but benchmarking or release
	lhs := append(FS, FSPayload[:(int(core.MaxPathLength)-1)*core.BlockLength]...)
	rhs, err := crypto.PRG(sharedKey16)
	if err != nil {
		log.Println("Couldn't create static randomness")
		return nil, err
	}
	rhs = rhs[core.SecurityParameter : core.BlockLength*int(core.MaxPathLength)]
	payloadTemp, err := xor(lhs, rhs)
	if err != nil {
		log.Println("Couldn't xor when adding the FS to the payload")
		return nil, err
	}

	payloadTempCopy := make([]byte, core.FSPayloadLength-core.SecurityParameter)
	copy(payloadTempCopy, payloadTemp)

	mac := crypto.GenericHMAC(sharedKey16, payloadTempCopy)

	nextFSPayload := append(mac, payloadTemp...)
	if len(nextFSPayload) != core.FSPayloadLength {
		err = errors.New("nextFSPayload has wrong length")
		log.Println(err)
		log.Printf("actual length: %v vs expected fixed length: %v\n", len(nextFSPayload), core.FSPayloadLength)
		return nil, err
	}

	return nextFSPayload, nil
}

// retrieveFSes corresponds to Algo 2 from HORNET
func retrieveFSes(keyToInitiateFS []byte, sharedSymKeys16 [][]byte, FSPayload core.FSPayload) ([][]byte, error) {
	payloadInit, err := crypto.PRG(keyToInitiateFS)
	if err != nil {
		log.Println("Couldn't initiate the FS")
		return nil, err
	}

	r := int(core.MaxPathLength)
	l := len(sharedSymKeys16)
	c := core.BlockLength

	FSes := make([][]byte, l)

	droppedTrailingBytes := payloadInit[(r-l)*c : r*c]
	for i := 0; i <= (l - 2); i++ {
		zeroBytes := make([]byte, (i+1)*c)
		mutation, err := crypto.PRG(sharedSymKeys16[i])
		if err != nil {
			log.Println("Couldn't create static randomness to reconstruct the trailing bytes")
			return nil, err
		}

		rhs := append(mutation[(r-l+i+1)*c:], zeroBytes...)

		droppedTrailingBytes, err = xor(droppedTrailingBytes, rhs)
		if err != nil {
			log.Println("Couldn't xor to reconstruct the trailing bytes")
			return nil, err
		}
	}

	payloadFull := append(FSPayload, droppedTrailingBytes...)

	for i := l - 1; i >= 0; i-- {
		// no need to copy here, the embedded copy is enough.
		mac := crypto.GenericHMAC(sharedSymKeys16[i], payloadFull[core.SecurityParameter:r*c])
		if !hmac.Equal(mac, payloadFull[:core.SecurityParameter]) {
			err = errors.New("mac is wrong")
			log.Println(err)
			return nil, err
		}

		zeroBytes := make([]byte, (i+1)*c)
		mutation, err := crypto.PRG(sharedSymKeys16[i])
		if err != nil {
			log.Println("Couldn't create static randomness to reconstruct the FS")
			return nil, err
		}
		rhs := append(mutation, zeroBytes...)

		payloadFull, err = xor(payloadFull, rhs)
		if err != nil {
			log.Println("Couldn't xor to reconstruct the FS")
			return nil, err
		}

		FSes[i] = make([]byte, core.FSLength)
		copy(FSes[i], payloadFull[core.SecurityParameter:core.BlockLength])

		payloadFull = payloadFull[core.BlockLength:]

	}

	return FSes, nil
}

// createSphinxAnswerPacket corresponds to step 1-4 of HORNET destination processing
// Checking the returned error is absolutely crucial as sphinxAnswerPacket might be partially modified by this function
func createSphinxAnswerPacket(packetDataHolder core.SetupPacket, sharedKey32 []byte, sphinxAnswerPacket *core.SetupPacket) (err error) {
	sphinxAnswerPacket.SphinxHDR, err = unwrapSphinxPayloadAtDest(sharedKey32, packetDataHolder.SphinxPayload)
	if err != nil {
		log.Println(err)
		return err
	}

	sphinxAnswerPacket.SphinxPayload, err = generateSphinxPayloadBackward(sharedKey32, packetDataHolder.FSPayload)
	if err != nil {
		log.Println(err)
		return err
	}

	sphinxAnswerPacket.FSPayload, err = crypto.PRG(cutDownSymKey(sharedKey32))
	if err != nil {
		log.Println(err)
		return err
	}

	sphinxAnswerPacket.CHDR = packetDataHolder.CHDR

	return nil
}

// encryptFS is the inverse function of decryptAndCheckFS.
// They are in different files as they are performed during different phases of the protocol.
// It is equivalent to HORNET's FS_CREATE
func encryptFS(nodeSecretKey []byte, decryptedFS core.DecryptedFS) ([]byte, error) {
	rawDecryptedFS := core.FSToBytes(decryptedFS)

	encryptedFS, err := crypto.PRP(nodeSecretKey, rawDecryptedFS)
	if err != nil {
		log.Println("Couldn't encrypt the FS")
		return nil, err
	}

	return encryptedFS, nil
}

//////////////// What HORNET abstracted //////////////////////
// For this part implementing SPHINX protocol basis, I intend on taking inspirations from
// https://github.com/nymtech/sphinx
// https://github.com/UCL-InfoSec/sphinx
// https://github.com/DonnchaC/sphinx
// Apart from obviously following the paper http://www0.cs.ucl.ac.uk/staff/G.Danezis/papers/sphinx-eprint.pdf
// And my own knowledge about mixnets
// Notably, the three repository listed above are not written in Go (but instead Rust, Python and a mix of Python and Assembly)
// So the whole code will be new, even though the logic and structure might follow those repositories.
// After a bit more research, I found 2 and a half Go implementations of Sphinx, that I will probably use as a library and wrap my functions around
// Those are: https://pkg.go.dev/github.com/mischief/go-sphinxmixcrypto and https://pkg.go.dev/github.com/david415/go-sphinxmixcrypto (the second being a more recent fork of the first)
// They do warn that those repos have not been cryptographically audited! But since my own project is not either for now, this would not taint the guarantees of my code.
// And https://pkg.go.dev/github.com/nymtech/nym-mixnet/sphinx which I tend to trust because it comes from Nym (and I'm biased). It is also more recent than the other repos.
// However, since Nym switched to Rust, the Go implementation is officially deprecated. As I don't intend to run Nym, but only use the Sphinx implementation, this should not be an issue (as long as Sphinx was correctly implemented)
// It seems that nym-go-sphinx might not have nice abstractions to generate the headers. Some functions might not be implemented.
// If I go from scratch, I could use nym-go-sphinx as inspiration for the field elements managements, take their processPacket implementation
// Sidenote: Go 1.20 finally resolve a long time issue of casting slice to arrays. At least Go 1.17 allows me to do it as well although in an ugly manner.
// But Go 1.20 also adds ECDH to the std lib, which would be very useful in coding sphinx from scratch.

// Actually, nym-go-sphinx has createHeaders, it is just not an exported function. 2 calls to createHeader could be used in generateSphinxHeader
// then encapsulateContent (also not exported) for generateSphinxPayload.
// getSharedSecrets (also not exported)
// ProcessSphinxPacket for processSphinxPacket, but careful that RoutingInfo and nextHop are probably designed with IP in mind.
// Not much about unwrapping function, but those are not the big issue (use AesCtr to remove the last layer of encryption)

// On the other hand, go-sphinxmixcrypto has a clear API to create SphinxHDR and SphinxPackets. I would rather have SphinxPayload over SphinxPackets, but I could maybe manage that manually by dissecting the code.
// My understanding is that their SphinxPacketUnwrap should be used by both the Unwrap and the process, depending on the content of the result field of an unwrapped message.

// I think my first choice will be go-sphinxmixcrypto, but I will make a commit right now, and if needed revert and focus on go-nym-sphinx.

// generateSphinxHeaders corresponds to HORNET naming GEN_SPHX_HDR
// It returns first the SphinxHDR Forward and then the SphinxHDR Backward.
// It also assigns the prepared symmetric session keys.
func (n *RequesterNode) generateSphinxHeaders(session *Session, chdr core.CHDR) (core.SphinxHDR, core.SphinxHDR, error, [][32]byte) {
	if chdr.Type != core.SetupType {
		err := errors.New("wrong CHDR type. shouldn't be happening")
		log.Println(err)
		return nil, nil, err, nil
	}
	// either create a separate MixHeaderFactory, at least for the way back!
	// Or modify the dependency... One option is to export the MixHeaderFactory of sphinxPacketFactory so it can be used for headers
	// Other is to modify the packetFactory to not have a mix header Factory field, but instead take the header as param of BuildForwardSphinxPacket
	// and have both a packet factory and a headerfactory. This requires the most "changes" (still lightweight), while sticking the closest to HORNET abstraction.
	// I chose that second option, hence why the library is included manually and not as a dependency.

	// Compute the mix header, and shared secrets for each hop.
	routeForward := make([][SphinxRouteLength]byte, len(session.pathingForward))
	for i, pathing := range session.pathingForward {
		nodetype := sphinxmixcrypto.MoreHops
		route := core.DataplanePathToSphinxBytes(pathing.Path, []byte("forw"), uint8(nodetype))
		routeForward[i] = *(*[SphinxRouteLength]byte)(route)
	}

	routeBackward := make([][SphinxRouteLength]byte, len(session.pathingBackward))
	for i, pathing := range session.pathingBackward {
		nodetype := sphinxmixcrypto.MoreHops
		route := core.DataplanePathToSphinxBytes(pathing.Path, []byte("back"), uint8(nodetype))
		routeBackward[i] = *(*[SphinxRouteLength]byte)(route)
	}

	/* Ok, I finally found what goes into the destination and messageID arguments:
	* When the last onion/mixing node removes the last layer, it will receive as "routing info" (destination||messageID)[:16]
	* So if I make destination length 16 bytes, it will only get destination as routing info.
	* This allows 1) final nodes to not be resolvers but OR-routers in an AS yet get the resolver address
	* 2) resolvers also acting as relay to identify self as the final destination (by setting destination as dataplanePathToSphinxBytes(lastPathing.Path, []byte("forw"), uint8(sphinxmixcrypto.ExitNode))
	* Those can be recovered on the other side by sphinxRoutingBytesToDataplanePath
	 */
	_ = routeForward[len(routeForward)-1][:]
	_ = routeBackward[len(routeBackward)-1][:]
	destinationForward := core.DataplanePathToSphinxBytes(session.pathingForward[len(session.pathingForward)-1].Path, []byte("ipv4"), sphinxmixcrypto.ExitNode)
	destinationBackward := core.DataplanePathToSphinxBytes(session.pathingBackward[len(session.pathingBackward)-1].Path, []byte("ipv4"), sphinxmixcrypto.ExitNode)

	var zeroDest [16]byte // TODO ?? messageID ??

	_ = []byte{byte(sphinxmixcrypto.MoreHops)}

	SHDRf, sharedSecretsForward32bytes, err := n.sphinxHeaderFactory.BuildHeader(routeForward, destinationForward, zeroDest)
	// this should produce the shared secret automatically
	if err != nil {
		log.Println(err)
		log.Println("Couldn't build the header forward")
		return nil, nil, err, nil
	}

	SHDRb, sharedSecretsBackward32bytes, err := n.sphinxHeaderFactory.BuildHeader(routeBackward, destinationBackward, zeroDest)
	// this should produce the shared secret automatically
	if err != nil {
		log.Println(err)
		log.Println("Couldn't build the header forward")
		return nil, nil, err, nil
	}

	// Trying to switch SPHINX to 16 bytes to fit HORNET was a mess, is still a mess, and might be impossible, if I want to stick to chacha20 and EC25519
	// So maybe the solution is to go back to 32 bytes SPHINX (still embed because of the library own dependencies failing), and simply keep half of the shared secret? It will still be shared and still be a secret.
	session.assignSessionSymKeys(sharedSecretsForward32bytes, sharedSecretsBackward32bytes)

	return SHDRf, SHDRb, nil, sharedSecretsForward32bytes
}

// assignSessionSymKeys takes the shared keys generated from the sphinx protocol and allocate them within the session structure,
func (s *Session) assignSessionSymKeys(symKeysForward, symKeysBackward [][32]byte) {
	s.sharedKeysForward = make([][]byte, len(s.pathingForward))
	s.sharedKeysBackward = make([][]byte, len(s.pathingBackward))
	for i := 0; i < len(s.pathingForward); i++ {
		s.sharedKeysForward[i] = symKeysForward[i][:]
	}

	// I made as a decision that 1) the recursive resolver has the same encoding as a relay
	// 2) the recursive resolver will use a single key for decrypting the request payload and encrypt the first layer of its response
	// So I need to ensure that from a requester point of view, the same key is used twice.
	// While I haven't formally proved it, I think it's not a critical privacy issue. On regular usage, nothing should be leaked
	// On malicious usage such as sending back as a DNS answer the exact request payload, it would break the privacy of the
	// first hop from the recursive resolver. Not a big deal as that recursive resolver anyways had the routing data for this hop.
	// Yet this does not change keys creation as the routing will also be taken from the last FS by the dest
	// and the first symKeyBackward is meant for the first relay. And the last for the requester to check the integrity

	for i := 0; i < len(s.pathingBackward); i++ {
		s.sharedKeysBackward[i] = symKeysBackward[i][:]
	}
}

// cutDownSymKey uniformises the downsize of keys from 32byte to 16byte for manipulating the FS and the data transmission phase.
func cutDownSymKey(len32 []byte) (len16 []byte) {
	if len(len32) != 32 {
		panic("wrong input key length")
	}
	return len32[16:]
}

// CutDownAllSymKeys must be called at the end of the sphinx setup.
func (s *Session) CutDownAllSymKeys() {
	for i := 0; i < len(s.sharedKeysForward); i++ {
		s.sharedKeysForward[i] = cutDownSymKey(s.sharedKeysForward[i])
	}
	for i := 0; i < len(s.sharedKeysBackward); i++ {
		s.sharedKeysBackward[i] = cutDownSymKey(s.sharedKeysBackward[i])
	}
}

// generateSphinxPayloadForward corresponds to HORNET naming GEN_SPHX_PL_SEND
// Note that compared to Sphinx 3.3, this only outputs delta0 while M0 (aka SHDRf) comes from generateSphinxHeaders and the message is reconstructed after
func (n *RequesterNode) generateSphinxPayloadForward(sharedKeysForward [][32]byte, SHDRf, SHDRb core.SphinxHDR) (core.SphinxPayload, error) {

	routeForward := make([][SphinxRouteLength]byte, len(n.session.pathingForward))
	for i, pathing := range n.session.pathingForward {
		nodetype := sphinxmixcrypto.MoreHops
		if i == len(n.session.pathingForward)-1 {
			nodetype = sphinxmixcrypto.ExitNode
		}
		route := core.DataplanePathToSphinxBytes(pathing.Path, []byte("forw"), uint8(nodetype))
		routeForward[i] = *(*[SphinxRouteLength]byte)(route)
	}

	firstHopBackward := core.DataplanePathToSphinxBytes(n.session.pathingBackward[0].Path, []byte("back"), uint8(sphinxmixcrypto.MoreHops))

	// TODO the second argument to BuildForwardSphinxPacket is the ClientID returned by the last unwrapping
	// So if last relay != resolver, it must be the resolver address (while last relay address is the last routing of the header)
	// But if for now, I assume that last relay == resolver, I can hijack that field for it to be the first NextHop of the backward path!!
	// And if this assumption breaks at some point, I now know how to use all those fields: header has the address of all the relays, while here I pass as second argument the address of the recursive resolver.
	// And I'd need to fix the unwrapping
	packet, err := n.sphinxPacketFactory.BuildForwardSphinxPacket(routeForward, *(*[SphinxRouteLength]byte)(firstHopBackward), core.SphinxHeaderToBytes(SHDRb), SHDRf, sharedKeysForward)
	if err != nil {
		log.Println(err)
		log.Println("Couldn't build the sphinxMixCrypto forward packet format")
		return nil, err
	}

	return packet.Payload, nil
}

// unwrapSphinxPayloadAtDest corresponds to HORNET naming UNWRAP_SPHX_PL_SEND
func unwrapSphinxPayloadAtDest(sharedKey []byte, sphinxPayloadForward core.SphinxPayload) (core.SphinxHDR, error) {
	// TODO this works fine, as long as the resolver is part of the onion-scheme. If the last node is a router which then forward to a resolver
	// well, not only I need to review a lot of the logic, but also the last layer should be regularly encrypted (against the router), and there should be a real decryption
	return core.BytesToSphinxHeader(sphinxPayloadForward), nil
}

// generateSphinxPayloadBackward corresponds to HORNET naming GEN_SPHX_PL_RECV
func generateSphinxPayloadBackward(sharedKey32 []byte, FSPayloadForward core.FSPayload) (core.SphinxPayload, error) {
	// Is this just a case of one layer of symmetric encryption?
	// It's more than that... This will get mutated many times by the relays. But encrypting it would require to know the sharedKeys, so impossible
	// So Option1: I deviate from Sphinx AND Hornet description of Sphinx and make it work more like HORNET (having a different processing on the way, back: essentially adding encryption). MEH.
	// Better Option2: I let the relays "remove unexisting encryption"?. In practice those are just PRP. Sounds good to me!
	// The trick is that unwrapSphinxPayloadAtSource needs to reverse all the PRPs.
	// Which is not what was designed in the Sphinx library I'm using.
	// But that sounds like the best option. Still need to manually add a layer here (like lines 129-134 of sphinxmixcrypto/node.go),
	// since the recursive resolver is not calling PacketUnwrap on the return packet!
	blockCipher := sphinxmixcrypto.NewLionessBlockCipher()
	deltaKey, err := blockCipher.CreateBlockCipherKey(*(*[32]byte)(sharedKey32))
	// careful about whether I do that with the cutdown to 16 or full 32. The relays will do it with 32. So the requester must have the 32 version stored.
	// So I need to change assignSessionSymKeys to keep the full 32, and then cut down to the 16 last bytes only at the end of the sphinx process.
	// but then I also need to change addFSToPayload use a 16bytes key currently, so retrieveFSes must be done in 16bytes as well.
	if err != nil {
		return nil, fmt.Errorf("createBlockCipherKey failure: %s", err)
	}
	delta, err := blockCipher.Decrypt(deltaKey, FSPayloadForward)
	if err != nil {
		return nil, fmt.Errorf("123 wide block cipher decryption failure: %s", err)
	}
	return delta, nil
}

// unwrapSphinxPayloadAtSource corresponds to HORNET naming UNWRAP_SPHX_PL_RECV
func (n *RequesterNode) unwrapSphinxPayloadAtSource(recurResolverSharedKey []byte, sharedKeysBackward [][]byte, sphinxPayloadBackward core.SphinxPayload) (core.FSPayload, error) {
	// need to add the one layer of symmetric encryption in generateSphinxPayloadBackward, and then remove the layers accordingly here.
	// need to manually do something similar to lines 250-267 of sphinxmixcrypto/client.go

	// First start by unwrapping the relays encryptions. Skip the very last key of sharedKeysBackward as this is the key of the source.
	delta := sphinxPayloadBackward
	for i := len(sharedKeysBackward) - 2; i > -1; i-- {
		blockCipherKey, err := n.sphinxPacketFactory.BlockCipher.CreateBlockCipherKey(*(*[32]byte)(sharedKeysBackward[i]))
		if err != nil {
			return nil, err
		}
		delta, err = n.sphinxPacketFactory.BlockCipher.Encrypt(blockCipherKey, delta)
		if err != nil {
			return nil, err
		}
	}
	// Then unwrap the first layer put on by the destination. Careful as it is done with the last key of the forwardSharedKeys!
	blockCipherKey, err := n.sphinxPacketFactory.BlockCipher.CreateBlockCipherKey(*(*[32]byte)(recurResolverSharedKey))
	if err != nil {
		return nil, err
	}
	delta, err = n.sphinxPacketFactory.BlockCipher.Encrypt(blockCipherKey, delta)
	if err != nil {
		return nil, err
	}

	return core.FSPayload(delta), nil
}

// processSphinxPacket corresponds to HORNET naming PROC_SPHX_PKT
// It is wrapped within processSphinxSetup which deviates from HORNET strict definition.
// sharedKey returned has 32 bytes
func (n *Node) processSphinxPacket(sphinxHDR core.SphinxHDR, sphinxPayload core.SphinxPayload) (nextSphinxHDR core.SphinxHDR, nextSphinxPayload core.SphinxPayload, sharedKey32, routing []byte, err error) {
	sphinxPacketLib := &sphinxmixcrypto.SphinxPacket{
		Header:  sphinxHDR,
		Payload: sphinxPayload,
	}

	// TODO include the replayCache in the Node struct. and take it from there: n.sphinxReplayCache. or get rid of it to remove state on relays..
	var replayCache sphinxmixcrypto.ReplayCache = mocks.NewSimpleReplayCache()

	unwrappedMessage, sharedSecret, err := sphinxmixcrypto.SphinxPacketUnwrap(core.DefaultSphinxParams(), replayCache, n.asymPrivateKey, sphinxPacketLib)
	if err != nil {
		log.Println(err)
		log.Println("Couldn't unwrap the packet while processing it")
		return nil, nil, nil, nil, err
	}

	nextSphinxPayload = unwrappedMessage.Delta
	sharedKey32 = sharedSecret

	switch unwrappedMessage.ProcessAction {
	case sphinxmixcrypto.MoreHops:
		nextSphinxHDR = &sphinxmixcrypto.MixHeader{
			Version:      0,
			EphemeralKey: *(*[32]byte)(unwrappedMessage.Alpha),
			RoutingInfo:  unwrappedMessage.Beta,
			HeaderMAC:    *(*[16]byte)(unwrappedMessage.Gamma),
		}
		path, ipv4, _ := core.SphinxRoutingBytesToDataplanePath(unwrappedMessage.NextHop)
		routing = core.DataplanePathToBytes(path, ipv4)
	case sphinxmixcrypto.ExitNode:
		// TODO routing must be set to 8 bytes of the return path! But how to get them? nextSphinxPayload is SHDRb
		// Could use ClientID? Certainly not the original intent of this field.
		// Or go back to using one more unwrapping, and setting one more routing hop on the forward to the first hop of the backward path.
		// So the first unwrapping gives the next hop (on the backward path), and the second unwrapping the real message?
		// But that means that this function must be processed differently by resolver than by relays.
		// (It would always return MoreHops, but resolver, would then re-call a variant of it through unwrapSphinxPayloadAtDest)
		// Currently using ClientID, see note in generateSphinxPayloadForward as well.
		path, ipv4, _ := core.SphinxRoutingBytesToDataplanePath(unwrappedMessage.ClientID)
		routing = core.DataplanePathToBytes(path, ipv4)
	}

	// unwrappedMessage.ProcessAction // TODO consider merging both relayProcess and resolverProcess, and then act based on the processAction (dest vs relay)
	// Otherwise, can also pass back the ProcessAction to check that it corresponds the type of node, a bit cumbersome as the calling function is node-type unaware, only two layers above the nodetype is known.

	return nextSphinxHDR, nextSphinxPayload, sharedKey32, routing, nil
}

