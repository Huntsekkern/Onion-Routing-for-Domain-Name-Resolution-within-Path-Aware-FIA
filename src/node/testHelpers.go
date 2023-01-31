package node

import (
	"crypto/rand"
	"github.com/scionproto/scion/pkg/snet"
	"log"
	"main.go/core"
	"time"
)

// generateExampleSessionFromPathing allows to bypass the Sphinx set-up for tests.
// It should work regardless of the path length.
// FS must be filled later!
func generateExampleSessionFromPathing(pathingForward, pathingBackward []snet.PacketInfo) Session {
	session := Session{
		pathingForward:  pathingForward,
		pathingBackward: pathingBackward,
		startTime: time.Now(),
		sharedKeysForward:  nil, // done below
		sharedKeysBackward: nil, // done below
		FSForward:          nil,
		FSBackward:         nil,
	}

	err := session.prepareFakeSessionSymKeys()
	if err != nil {
		log.Println("Error while generating symmetric keys")
	}

	return session
}


// prepareFakeSessionSymKeys generates random sharedKeys for each hop of the s session. In practice, those keys are established by the sphinx protocol.
func (s *Session) prepareFakeSessionSymKeys() error {
	s.sharedKeysForward = make([][]byte, len(s.pathingForward))
	s.sharedKeysBackward = make([][]byte, len(s.pathingBackward))
	for i := 0; i < len(s.pathingForward); i++ {
		s.sharedKeysForward[i] = make([]byte, core.SecurityParameter)
		bytesAmount, err := rand.Read(s.sharedKeysForward[i])
		if err != nil || bytesAmount != core.SecurityParameter {
			log.Println("Error while generating random SymKeys")
			log.Println(err)
			return err
		}
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
		s.sharedKeysBackward[i] = make([]byte, core.SecurityParameter)
		bytesAmount, err := rand.Read(s.sharedKeysBackward[i])
		if err != nil || bytesAmount != core.SecurityParameter {
			log.Println("Error while generating random SymKeys")
			log.Println(err)
			return err
		}
	}

	return nil
}
