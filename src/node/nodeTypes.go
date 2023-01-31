package node

import (
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/app/appnet"
	"main.go/go-sphinxmixcrypto"
	"time"
)

// Node is a common structure for the three types of nodes
type Node struct {
	config          appnet.NetworkConfig
	daemonConnector daemon.Connector
	network         snet.SCIONNetwork
	conn            *snet.Conn
	scionConn       snet.SCIONPacketConn
	inputChan       chan snet.Packet
	outputChan      chan snet.Packet
	onioning        bool
	// TODO it must be noted that current implementation use a random but permanent secretKey. A real implementation should rotate this secretKey once in a while (while keeping a backup of the old one for a while to not invalidate all ongoing sessions)
	// secretKey Length should be SecurityParameter (= 16), but want it typed as a slice.
	secretKey      []byte
	sphinxParams   sphinxmixcrypto.SphinxParams
	asymPrivateKey sphinxmixcrypto.PrivateKey
}

// RequesterNode is a wrapper around Node which also includes some additional structure notably to store the session state.
type RequesterNode struct {
	node                Node
	sessionDuration     time.Duration
	session             Session
	sphinxHeaderFactory *sphinxmixcrypto.MixHeaderFactory
	sphinxPacketFactory *sphinxmixcrypto.SphinxPacketFactory
}

// Session allows for any asymmetric protocol, but I'm currently using ED25519
type Session struct {
	// While the pathing is stored in session as changing the pathing would require creating a new session
	// and updating those values, they do not need to be reset when the session expires because of time.
	pathingForward  []snet.PacketInfo
	pathingBackward []snet.PacketInfo

	// Values below are to be reset per session
	startTime time.Time
	sharedKeysForward  [][]byte
	sharedKeysBackward [][]byte

	// Values below are reset per session and only obtained through the set-up phase.
	FSForward  [][]byte
	FSBackward [][]byte
}

type ignoreSCMP struct{}

func (ignoreSCMP) Handle(pkt *snet.Packet) error {
	// Always reattempt reads from the socket.
	return nil
}

