package node

import (
	"context"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
	"log"
	"main.go/core"
	"net"
)

// This file contains methods related to SCION networking such as getting the pathing and read and write packets.

// Listen is blocking and is called through a goroutine. Upon receiving a packet,
// Listen queue the packet to the node channel
func (n *Node) Listen() (snet.Packet, error){
	var packet snet.Packet

	// ov seems irrelevant here? Just a way to get the lastHop into a pointer?
	err := n.scionConn.ReadFrom(&packet, nil)
	if err != nil {
		log.Println(err)
		log.Println("Node couldn't read a packet")
		return snet.Packet{}, err
	}

	err = packet.Decode()
	if err != nil {
		log.Println(err)
		log.Println("Node couldn't deserialize the packet received")
		return snet.Packet{}, err
	}

	return packet, nil
}

// Send is blocking and goes into the next iteration when an outgoing packet is added to the node queue.
// It could be called by a goroutine, but shouldn't if it's the last function call of the node main function.
func (n *Node) Send(packet snet.Packet) error {

	// should probably serialize the packets even when onioning
	err := packet.Serialize()
	if err != nil {
		log.Println(err)
		log.Println("Node couldn't serialize the packet to send")
		return err
	}

	// TODO very unsure what ov even stands for
	// And those hardcoded ports for every sent message can't be right
	ov := &net.UDPAddr{
		IP:   packet.Destination.Host.IP(),
		Port: 2222,
		Zone: "",
	}

	err = n.scionConn.WriteTo(&packet, ov)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

// getHopByHopPaths returns the forward and backward paths from the local node to a remote node (typically the recursive resolver)
func (n *Node) getHopByHopPaths(localAddr snet.SCIONAddress, remoteAddr snet.SCIONAddress) (forwardPath, backwardPath []snet.PacketInfo) {
	//return getHardcodedHopByHopPath()

	forwardPath = n.getHopByHopPathOneWay(localAddr, remoteAddr)
	backwardPath = n.getHopByHopPathOneWay(remoteAddr, localAddr)
	return forwardPath, backwardPath
}

// getHopByHopPathOneWay returns the path from a node to another node (typically the local node and the recursive resolver) through SCION daemonConnector.
func (n *Node) getHopByHopPathOneWay(from snet.SCIONAddress, to snet.SCIONAddress) []snet.PacketInfo {
	paths, err := n.daemonConnector.Paths(context.Background(), to.IA, from.IA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		log.Fatalf("Failed to lookup core paths: %v:", err)
	}
	selectedPathMetadata := paths[0].Metadata()

	pathing := make([]snet.PacketInfo, len(selectedPathMetadata.InternalHops)+1)

	for i := range pathing {
		// TODO some SCION functions clearly define interface ID as uint16 while other do it as common.IFIDType aka uint64
		// I don't know what SCION expects, but I'm just going to cut them down to uint16.
		egressID := selectedPathMetadata.Interfaces[2*i].ID
		ingressNextID := selectedPathMetadata.Interfaces[2*i+1].ID
		dpath := core.NewOneHopFull(uint16(egressID), uint16(ingressNextID))
		packetInfo := snet.PacketInfo{
			// TODO according to Matthias, no need for dest/source
			Destination: snet.SCIONAddress{},
			Source:      snet.SCIONAddress{},
			Path:        dpath,
		}
		pathing[i] = packetInfo
	}

	return pathing
}

//////////////////////////////////////////////////////////////////////////////
// The code excerpts below were initial tries to deal with SCION headers and packet structure.
// I could not test those, but it seems that it should be possible to rely on Serialize and Decode and save some time.
// If not, those process should be integrated within Send and Listen.

/*
Instead of using packet.Decode if need more flexibility
var scn slayers.SCION
var hbh slayers.HopByHopExtnSkipper
var e2e slayers.EndToEndExtnSkipper
var udp slayers.UDP
var scmp slayers.SCMP
var pld gopacket.Payload
parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION, &scn, &hbh, &e2e, &udp, &scmp, &pld)
decoded := []gopacket.LayerType{}

	if err := parser.DecodeLayers(packetData, &decoded); err != nil {
		// Handle error
	}

	for _, layerType := range decoded {
		// Handle layers
	}
*/

/*
func createPackedData(payload []byte) snet.Bytes {
	// I will need to manually manage the SCION header so as to only reveal the next hop
	s := &slayers.SCION{}
	// I could include the OR header in the HopByHopExtn header??? Both Common and AHDR!
	// But I need to have an extension number for this. And my extension is obviously not officially registered...
	// + SCION states that a border router is only required to process at min 3 headers,
	//which could kill my project then.
	// So maybe for now, it's easier to include my headers as part of the payload,
	//and assume dedicated routers which onion mode is turned on.
	// Then the payload only have to be encrypted/decrypted and the relevant data is fetched from the HDRs
	hbh := &slayers.HopByHopExtn{}
	udp := &slayers.UDP{}
	pld := gopacket.Payload(payload)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	if err := gopacket.SerializeLayers(buf, opts, s, hbh, udp, pld); err != nil {
		// Handle error
		log.Println(err)
	}
	return buf.Bytes()
}
 */

// use router, path, dataplanepath and slayers.scion package!
/*
	run, err := showpaths.Run(context.Background(), ,) // to get the path to an ISD-AS printed to stdout,
	// so would need to modify this
	// otherwise:
	segfetcher.Pather{
		IA:         0,
		MTU:        0,
		NextHopper: nil,
		RevCache:   nil,
		Fetcher:    nil,
		Splitter:   nil,
	}.GetPaths()
*/

/*
	var scn slayers.SCION
	var hbh slayers.HopByHopExtnSkipper
	var e2e slayers.EndToEndExtnSkipper
	var udp slayers.UDP
	var scmp slayers.SCMP
	parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION, &scn, &hbh, &e2e, &udp, &scmp, &pld)
	decoded := []gopacket.LayerType{}
	if err := parser.DecodeLayers(packet.Bytes, &decoded); err != nil {
		// Handle error
		log.Println(err)
	}
	for _, layerType := range decoded {
		// Handle layers
		log.Println(layerType)
	}
*/