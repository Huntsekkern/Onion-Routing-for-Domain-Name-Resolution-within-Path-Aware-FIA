package node

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/sock/reliable"
	"github.com/scionproto/scion/pkg/sock/reliable/reconnect"
	"github.com/scionproto/scion/private/app/appnet"
	"log"
	"main.go/core"
	"main.go/go-sphinxmixcrypto"
	"net"
	"time"
)

// initNode initialise some default value for a node
func initNode(keyState sphinxmixcrypto.PrivateKey) Node {
	node := Node{}
	node.inputChan = make(chan snet.Packet)
	node.outputChan = make(chan snet.Packet)
	defer close(node.inputChan)
	defer close(node.outputChan)

	node.secretKey = make([]byte, core.SecurityParameter)
	_, err := rand.Read(node.secretKey)
	if err != nil {
		panic("Couldn't read randomness for the secretKey. Node not running")
	}

	node.asymPrivateKey = keyState

	return node
}

// CreateScionPacketConn should set-up all the SCION structure within a node and get it ready to send/listen. Might not work though.
func (n *Node) CreateScionPacketConn(localAddr snet.SCIONAddress, public *net.UDPAddr, sciondAddr, dispatcherSocket string) {
	var err error
	ctx := context.Background()

	var localAddrUDP snet.UDPAddr
	localIp := localAddr.Host.IP()
	var listen *net.UDPAddr
	listen = &net.UDPAddr{
		IP:   localIp,
		Port: 1111, // TODO probably need to have one ingress and egress port? But so also one in and out PacketConn
		Zone: "",
	}
	localAddrUDP = snet.UDPAddr{
		IA:      localAddr.IA,
		Path:    nil,
		NextHop: nil,
		Host:    listen,
	}

	n.daemonConnector, err = daemon.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		log.Fatal("Failed to create SCION connector:", err)
	}

	n.config = appnet.NetworkConfig{
		IA:                    localAddr.IA,
		Public:                public, // TODO?
		ReconnectToDispatcher: false,
	}

	/*pds := &snet.DefaultPacketDispatcherService{
		Dispatcher:             reliable.NewDispatcher(""),
		SCMPHandler:            ignoreSCMP{},
		SCIONPacketConnMetrics: n.config.SCIONPacketConnMetrics,
	}*/
	pds := &snet.DefaultPacketDispatcherService{
		Dispatcher: reconnect.NewDispatcherService(
			reliable.NewDispatcher(dispatcherSocket)),
		SCMPHandler: snet.DefaultSCMPHandler{
			RevocationHandler: daemon.RevHandler{Connector: n.daemonConnector},
		},
		SCIONPacketConnMetrics: n.config.SCIONPacketConnMetrics,
	}

	n.network = snet.SCIONNetwork{
		LocalIA:     n.config.IA,
		Dispatcher:  pds,
		ReplyPather: nil,
		Metrics:     n.config.SCIONNetworkMetrics,
	}
	// the Listen call below takes care of registering the Dispatcher!
	// TODO it fails with dial unix /run/shm/dispatcher/default.sock: connect: A socket operation encountered a dead network.
	// TODO THIS IS CRUCIALLY SOMETHING I MUST FIX
	// /run/shm/dispatcher/default.sock <- this address is defaultDisPath in reliable.go
	// aka what is provided when at line 22 I use name = "" instead of giving an address
	// And it is what is passed to reliable.Dial as the address parameter
	conn, err := n.network.Listen(context.Background(), "udp", localAddrUDP.Host, addr.SvcNone)
	if err != nil {
		log.Println(err)
	}
	n.scionConn = snet.SCIONPacketConn{
		Conn:        conn,
		SCMPHandler: nil,
		Metrics:     n.config.SCIONPacketConnMetrics,
	}
}

// isSessionExpired checks if a session is expired from the session start time and its duration (known to the requester)
func isSessionExpired(sessionStart time.Time, maxDuration time.Duration) bool {
	return sessionStart.Add(maxDuration).Before(time.Now())
}

// isEXPExpired checks if a session is expired from the EXP time value in bytes (included in the CHDR and FSes)
func isEXPExpired(EXP []byte) bool {
	EXPint := int64(binary.BigEndian.Uint64(EXP))
	return time.Now().After(time.Unix(EXPint, 0))
}

// xor basically xor two bytes slices bit by bit. The slices must have the same length
func xor(a []byte, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		err := errors.New("length of arrays to xor not equal")
		log.Println(err)
		return nil, err
	}
	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}
	return res, nil
}

