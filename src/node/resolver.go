package node

import (
	"github.com/miekg/dns"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"log"
	"main.go/core"
	"main.go/crypto"
	"main.go/mocks"
)

// RunRecursiveResolverNode takes as parameters some information such as the NS, the mode (Onion-routing or not),
// but then behaves as a server: permanently running and listening for incoming queries.
// nameserver needs to match the addr and port of the CoreDNS node but defaults to "127.0.0.1:1053"
// The CoreDNS server must be started with ./coredns -dns.port=1053 -conf Corefile (or equivalent)
func RunRecursiveResolverNode(onioning bool, localAddr snet.SCIONAddress, nameserver string, sciondAddr string, dispatcherSocket string) {

	node := initNode(mocks.DefaultResolverKeyStateHardcoded())
	node.onioning = onioning // from CLI args
	node.CreateScionPacketConn(localAddr, nil, sciondAddr, dispatcherSocket)

	go func() {
		for {
			packet, err := node.Listen()
			if err != nil {
				log.Println("Recursive Resolver couldn't listen for packets")
				break
			}
			node.inputChan <- packet
		}
	}()

	if node.onioning {
		go node.processOnionAtRecursiveResolver(nameserver)
	} else {
		go node.processAtRecursiveResolver(nameserver)
	}

	// that was done to avoid having the node shutting instantly. Could also do a chan for a graceful shutdown
	// go node.send()
	for {
		packet := <-node.outputChan
		err := node.Send(packet)
		if err != nil {
			log.Println("Recursive Resolver couldn't output the packet")
			return
		}
	}

}

// processAtRecursiveResolver is called for non-onion packets and should resolve the DNS query to the nameserver and answer with it.
func (n *Node) processAtRecursiveResolver(nameserver string) {
	dnsClient := new(dns.Client)
	dnsClient.Net = "udp"

	for {
		packet := <-n.inputChan

		// Sending query to the CoreDNS node
		pureDNSpayload, err := n.resolveRecursively(dnsClient, packet.Payload.(snet.UDPPayload).Payload, nameserver)
		if err != nil {
			log.Println("Couldn't resolve recursively")
			log.Println(err)
			return
		}
		udpPayload := snet.UDPPayload{
			SrcPort: packet.Payload.(snet.UDPPayload).DstPort,
			DstPort: packet.Payload.(snet.UDPPayload).SrcPort,
			Payload: pureDNSpayload,
		}
		var replyPacket snet.Packet
		replyPacket.Payload = udpPayload

		replyPacket.Source = packet.Destination
		replyPacket.Destination = packet.Source

		// Reverse the path. Weird that it's so hard to do...
		// probably because the intended usage is to actually query for a path to the daemon.
		var decoded scion.Decoded
		err = decoded.DecodeFromBytes(packet.Path.(path.SCION).Raw)
		if err != nil {
			log.Println("Couldn't decode the forward path")
			log.Println(err)
			return
		}
		backwardPath, err := decoded.Reverse()
		if err != nil {
			log.Println("Couldn't reverse the forward path")
			log.Println(err)
			return
		}
		dpathback := make([]byte, decoded.Len())
		err = backwardPath.SerializeTo(dpathback)
		if err != nil {
			log.Println("Couldn't serialize the backward path")
			log.Println(err)
			return
		}
		replyPacket.Path = path.SCION{Raw: dpathback}


		// Just figure out the next address. Not even?? or is that the ov
		n.outputChan <- replyPacket
	}

}

// processOnionAtRecursiveResolver is called for onion packets, will process the packet according to the phase
// and send it backwards to the next node as determined from the routing info.
func (n *Node) processOnionAtRecursiveResolver(nameserver string) {
	dnsClient := new(dns.Client)
	dnsClient.Net = "udp"

	for {
		packet := <-n.inputChan

		var SCIONPacketToSendBack snet.Packet

		chdrIn := packet.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		switch chdrIn[0] {
		case core.SetupType:
			err := n.resolverProcessSphinxSetup(packet, &SCIONPacketToSendBack)
			if err != nil {
				log.Println("Couldn't process a sphinx packet at resolver")
				log.Println(err)
				break
			}
		case core.DataTypeForward:
			err := n.resolverProcessDataTypeForward(packet, &SCIONPacketToSendBack, dnsClient, nameserver)
			if err != nil {
				log.Println("Couldn't process a datatypeForward at resolver")
				log.Println(err)
				break
			}
		case core.DataTypeBackward:
			log.Println("Recursive Resolver shouldn't have to process a DataTypeBackward")
			break
		default:
			log.Printf("Packet Type doesn't match one of the 3 options: %v\n", chdrIn[0])
		}

		n.outputChan <- SCIONPacketToSendBack
	}
}

// resolverProcessSphinxSetup processes the snet.Packet type of the sphinx phase. It is used by the resolver.
// It is different from processSphinxSetup (which is one level lower, manipulating
// SetupPacket) and from processSphinxPacket which corresponds to HORNET PROC_SPHX_PKT.
func (n *Node) resolverProcessSphinxSetup(packet snet.Packet, nextPacket *snet.Packet) error {
	sphinxPacket := core.BytesToSetupPacket(packet.Payload.(snet.UDPPayload).Payload)

	// fake because this is not the one to send, it's just a structure holding relevant content
	var fakeNextSphinxPacket core.SetupPacket

	sharedKey32, routing, err := n.processSphinxSetup(sphinxPacket, &fakeNextSphinxPacket)
	if err != nil {
		log.Println("Couldn't process the inner sphinx packet")
		return err
	}

	var sphinxAnswerPacket core.SetupPacket

	err = createSphinxAnswerPacket(fakeNextSphinxPacket, sharedKey32, &sphinxAnswerPacket)
	if err != nil {
		log.Println("Couldn't create the sphinxAnswerPacket")
		return err
	}

	rawSphinxAnswerPacket := core.SetupPacketToBytes(sphinxAnswerPacket)

	udpPayload := snet.UDPPayload{
		SrcPort: 0, // TODO
		DstPort: 0, // TODO
		Payload: rawSphinxAnswerPacket,
	}
	nextPacket.Payload = udpPayload
	nextPacket.Path, _ = core.RoutingBytesToDataplanePath(routing)

	return nil
}

// resolverProcessDataTypeForward removes the last layer of encryption, resolve the dns query and encrypt the first layer
// before sending it on the backward path.
func (n *Node) resolverProcessDataTypeForward(packet snet.Packet, nextPacket *snet.Packet, dnsClient *dns.Client, nameserver string) error {
	finalPayload, R, sharedKey, err := n.removeLayer(packet.Payload.(snet.UDPPayload).Payload, true)
	if err != nil {
		log.Println("Couldn't decrypt the packet at resolver")
		return err
	}

	decryptedPayload := finalPayload[core.CHDRLength:]

	//AHDRf := decryptedPayload[:core.AHDRLength] // This is garbage randomness, as there's no more FS/next routing
	AHDRb := decryptedPayload[core.AHDRLength : 2*core.AHDRLength]
	query := decryptedPayload[2*core.AHDRLength : len(decryptedPayload)-core.SecurityParameter]
	IV0b := decryptedPayload[len(decryptedPayload)-core.SecurityParameter:]

	// Sending query to the CoreDNS node
	pureDNSpayload, err := n.resolveRecursively(dnsClient, query, nameserver)
	if err != nil {
		log.Println("Couldn't resolve recursively")
		return err
	}

	// As per testHelpers.go prepareFakeSessionSymKeys comment, the symKey for the encryption as resolver == the symKey for the decryption
	O0b, err := crypto.ENC(sharedKey, IV0b, pureDNSpayload, core.DataPaddingFactor, true)
	if err != nil {
		log.Println("Couldn't encrypt the first layer of the onion back")
		return err
	}
	chdr := make([]byte, 0)
	chdr = append(chdr, core.DataTypeBackward, core.MaxPathLength)
	chdr = append(chdr, IV0b...)
	payloadBack := append(chdr, AHDRb...)
	payloadBack = append(payloadBack, O0b...)


	udpPayload := snet.UDPPayload{
		SrcPort: 04104, // TODO
		DstPort: 04104, // TODO
		Payload: payloadBack,
	}
	nextPacket.Payload = udpPayload
	nextPacket.Path, _ = core.RoutingBytesToDataplanePath(R)

	return nil
}

// resolveRecursively takes a non-encrypted payload and return a non-encrypted byte slice made from the packed dnsReply
// This node will have a fixed nameserver running CoreDNS for a given subset of zones.
// CoreDNS might be running in or out the SCION network. Since I want to avoid modifying CoreDNS,
// I think it will be out of SCION. So this will be a process of sending a regular packet with a regular conn
// and waiting for the answer. As the answer is received, transform it back into SCION world.
func (n *Node) resolveRecursively(client *dns.Client, rawDnsQuery []byte, nameserver string) ([]byte, error) {
	// retrieve m from payload (This assumes no-onion-encryption at this stage)
	m := new(dns.Msg)
	if err := m.Unpack(rawDnsQuery); err != nil {
		log.Println(err)
		log.Println("Couldn't unpack the payload to a dns message")
		return nil, err
	}

	// nameserver defaults to "127.0.0.1:1053" but can also be specified when starting the node
	// It needs to match the addr and port of the CoreDNS node, which can be started with
	// ./coredns -dns.port=1053 -conf Corefile
	r, _, err := client.Exchange(m, nameserver)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	pureDNSpayload, err := r.Pack()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return pureDNSpayload, nil
}
