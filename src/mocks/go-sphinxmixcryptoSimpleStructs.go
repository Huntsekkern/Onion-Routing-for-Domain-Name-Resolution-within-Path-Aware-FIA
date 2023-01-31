package mocks

import (
	"encoding/hex"
	"gitlab.com/yawning/chacha20.git"
	"main.go/go-sphinxmixcrypto"
)

// This file contains the implementations from go-sphinxmixcrypto of its own interfaces. Meant for testing.

type SimpleKeyState struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
	Id         [16]byte
}

func (v *SimpleKeyState) GetPrivateKey() [32]byte {
	return v.PrivateKey
}

// DummyPKI implements the SphinxPKI interface
// however this is only really useful for testing
// mixnet functionality on a single machine.
type DummyPKI struct {
	nodeKeyStateMap map[[16]byte]*SimpleKeyState
}

// NewDummyPKI creates a new DummyPKI
func NewDummyPKI(nodeKeyStateMap map[[16]byte]*SimpleKeyState) *DummyPKI {
	return &DummyPKI{
		nodeKeyStateMap: nodeKeyStateMap,
	}
}

// Get returns the public key for a given identity.
// PKIKeyNotFound is returned upon failure.
func (p *DummyPKI) Get(id [16]byte) ([32]byte, error) {
	nilKey := [32]byte{}
	_, ok := p.nodeKeyStateMap[id]
	if ok {
		return p.nodeKeyStateMap[id].PublicKey, nil
	}
	return nilKey, sphinxmixcrypto.ErrorPKIKeyNotFound
}

// Identities returns all the identities the PKI knows about.
func (p *DummyPKI) Identities() [][16]byte {
	var identities [][16]byte
	for id := range p.nodeKeyStateMap {
		identities = append(identities, id)
	}
	return identities
}

type ChachaEntropyReader struct {
	cipher *chacha20.Cipher
}

func NewChachaEntropyReader(keyStr string) (*ChachaEntropyReader, error) {
	key, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, err
	}
	var nonce [8]byte
	cipher, err := chacha20.New(key[:], nonce[:])
	if err != nil {
		return nil, err
	}
	reader := ChachaEntropyReader{
		cipher: cipher,
	}
	return &reader, err
}

func (r *ChachaEntropyReader) Read(data []byte) (int, error) {
	readLen := len(data)
	buf := make([]byte, readLen)
	r.cipher.XORKeyStream(data, buf)
	return readLen, nil
}

type SimpleReplayCache struct {
	seenSecrets map[[32]byte]bool
}

func NewSimpleReplayCache() *SimpleReplayCache {
	state := SimpleReplayCache{
		seenSecrets: make(map[[32]byte]bool),
	}
	return &state
}

func (v *SimpleReplayCache) Get(tag [32]byte) bool {
	_, ok := v.seenSecrets[tag]
	return ok
}

func (v *SimpleReplayCache) Set(tag [32]byte) {
	v.seenSecrets[tag] = true
}

func (v *SimpleReplayCache) Flush() {
	v.seenSecrets = make(map[[32]byte]bool)
}
