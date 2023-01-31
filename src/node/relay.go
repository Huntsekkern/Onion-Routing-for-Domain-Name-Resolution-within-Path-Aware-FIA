package node

import (
	"github.com/scionproto/scion/pkg/snet"
	"log"
	"main.go/core"
	"main.go/mocks"
)

// RunRelayNode takes as parameter the mode of operation (Onion or plain) and then behaves as a router
func RunRelayNode(onioning bool, localAddr snet.SCIONAddress, sciondAddr string, dispatcherSocket string) {

	node := initNode(mocks.DefaultResolverKeyStateHardcoded())
	node.onioning = onioning // from CLI args
	node.CreateScionPacketConn(localAddr, nil, sciondAddr, dispatcherSocket)

	go func() {
		for {
			packet, err := node.Listen()
			if err != nil {
				log.Println("Relay couldn't listen for packets")
				break
			}
			node.inputChan <- packet
		}
	}()

	if node.onioning {
		go node.processOnionAtRelay()
	} else {
		go node.processAtRelay()
	}

	// that was done to avoid having the node shutting instantly. Could also do a chan for a graceful shutdown
	// go node.send()
	for {
		packet := <-node.outputChan
		err := node.Send(packet)
		if err != nil {
			log.Println("Relay couldn't output the packet")
			return
		}
	}

	// Will work with PacketConn as, although we have a session, we don't really have a stream.
	// And a OR router is closer to doing packet per packet forwarding.
	// A scionPacketConn
	// which only takes as input valid snet.Packet
	// whose snet.PacketInfo is only about the next hop (
	// the real packetInfo being onion-encrypted in the payload of PacketInfo)
}

// processAtRelay is called for non-onion packets and should just forward the packet without touching it.
func (n *Node) processAtRelay() {
	for {
		packet := <-n.inputChan

		var nextPacket snet.Packet
		// Just figure out the next address. Not even?? or is that the ov from the API?? (readFrom in listen)
		copy(nextPacket.Bytes, packet.Bytes)
		n.outputChan <- nextPacket
	}
}

// processOnionAtRelay is called for onion packets, will modify the packet according to the phase and the direction
// and send it to the next node as determined from the routing info.
func (n *Node) processOnionAtRelay() {
	for {
		packet := <-n.inputChan

		var nextPacket snet.Packet

		chdrIn := packet.Payload.(snet.UDPPayload).Payload[:core.CHDRLength]
		switch chdrIn[0] {
		case core.SetupType:
			err := n.relayProcessSphinxSetup(packet, &nextPacket)
			if err != nil {
				log.Println("Couldn't process a sphinx packet")
				log.Println(err)
				break
			}
		case core.DataTypeForward:
			err := n.relayProcessDataTypeForward(packet, &nextPacket)
			if err != nil {
				log.Println("Couldn't process a datatypeForward")
				log.Println(err)
				break
			}
		case core.DataTypeBackward:
			err := n.relayProcessDataTypeBackward(packet, &nextPacket)
			if err != nil {
				log.Println("Couldn't process a datatypeBackward")
				log.Println(err)
				break
			}
		default:
			log.Printf("Packet Type doesn't match one of the 3 options: %v\n", chdrIn[0])
		}

		n.outputChan <- nextPacket
	}
}

// relayProcessSphinxSetup processes the snet.Packet type of the sphinx phase. It is used by the relay on both forward and backward paths.
// It is different from processSphinxSetup (which is one level lower, manipulating
// SetupPacket) and from processSphinxPacket which corresponds to HORNET PROC_SPHX_PKT.
func (n *Node) relayProcessSphinxSetup(packet snet.Packet, nextPacket *snet.Packet) (err error) {
	sphinxPacket := core.BytesToSetupPacket(packet.Payload.(snet.UDPPayload).Payload)

	var nextSphinxPacket core.SetupPacket

	_, routing, err := n.processSphinxSetup(sphinxPacket, &nextSphinxPacket)
	if err != nil {
		log.Println("Couldn't process the inner sphinx packet")
		return err
	}

	rawNextSetupPacket := core.SetupPacketToBytes(nextSphinxPacket)

	udpPayload := snet.UDPPayload{
		SrcPort: 0, // TODO
		DstPort: 0, // TODO
		Payload: rawNextSetupPacket,
	}

	// are source/dest needed? not according to Matthias Frei
	nextPacket.Payload = udpPayload
	nextPacket.Path, _ = core.RoutingBytesToDataplanePath(routing)

	return nil
}

// relayProcessDataTypeForward is a small factorisation, not crucial, but it helps to keep the processOnion function clean
// and allows for high-level (SCION packets) but non-network testing.
func (n *Node) relayProcessDataTypeForward(packet snet.Packet, nextPacket *snet.Packet) error {
	nextPayload, R, _, err := n.removeLayer(packet.Payload.(snet.UDPPayload).Payload, false)
	if err != nil {
		log.Println("Couldn't remove an onion layer to the payload to forward")
		return err
	}
	udpPayload := snet.UDPPayload{
		SrcPort: 0, // TODO
		DstPort: 0, // TODO
		Payload: nextPayload,
	}
	nextPacket.Payload = udpPayload
	nextPacket.Path, _ = core.RoutingBytesToDataplanePath(R)

	return nil
}

// relayProcessDataTypeBackward is a small factorisation, not crucial, but it helps to keep the processOnion function clean
// and allows for high-level (SCION packets) but non-network testing.
func (n *Node) relayProcessDataTypeBackward(packet snet.Packet, nextPacket *snet.Packet) error {
	nextPayload, R, err := n.addLayer(packet.Payload.(snet.UDPPayload).Payload)
	if err != nil {
		log.Println("Couldn't add an onion layer to the payload to forward")
		return err
	}
	udpPayload := snet.UDPPayload{
		SrcPort: 0, // TODO
		DstPort: 0, // TODO
		Payload: nextPayload,
	}
	nextPacket.Payload = udpPayload
	nextPacket.Path, _ = core.RoutingBytesToDataplanePath(R)

	return nil
}

