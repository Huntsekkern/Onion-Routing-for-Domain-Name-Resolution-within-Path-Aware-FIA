package node

import (
	"crypto/hmac"
	"errors"
	"log"
	"main.go/core"
	"main.go/crypto"
)

// This file contains functions related to the onion encryption of the data transmission phase.

// removeLayer returns the full payload of the next packet from the CHDR, AHDR and OnionPayload
// The second slice returned contains the raw routing information (i.e., next HopField)
// The source/requester can't simply use this function. It needs to be adapted to take a parameter to differentiate the MAC checking and no FS decryption
func (n *Node) removeLayer(rawDataPacket []byte, lastLayer bool) (nextRawDataPacket []byte, R []byte, sharedKey []byte, err error) {
	dataPacket := core.BytesToDataPacket(rawDataPacket)

	decryptedFS, err := decryptAndCheckFS(n.secretKey, dataPacket.AHDR.FS)
	if err != nil {
		log.Println("Error while decrypting the FS")
		return nil, nil, nil, err
	}

	sharedKey = decryptedFS.SharedKey
	R = decryptedFS.Routing

	// Check the mac

	// For some reason (GC?), calling MAC, change my local MacValue. So I'm using this trick to force a valid comparison.
	macReceivedCopy := make([]byte, len(dataPacket.AHDR.Mac))
	copy(macReceivedCopy, dataPacket.AHDR.Mac)

	// Same issue the Onion also get changed, here by the MAC() and on the lhs := append again...
	OnionCopy := make([]byte, len(dataPacket.DataPayload))
	copy(OnionCopy, dataPacket.DataPayload)

	// Same issue the Blinded also get changed, here by the MAC() and on the lhs := append again...
	BlindedCopy := make([]byte, len(dataPacket.AHDR.Blinded))
	copy(BlindedCopy, dataPacket.AHDR.Blinded)

	// I solved the mystery with the above lines, but if I want to investigate more, a curious impact of MAC is that the 16 first bytes of Blinded becomes the 16 bytes of MacReceived
	// Checking the mac must only include Onion on the forwardPath. i.e. when removing a layer, not when addingLayer
	macComputed := crypto.MAC(sharedKey, dataPacket.CHDR.IVorEXP, dataPacket.AHDR.FS, dataPacket.AHDR.Blinded, dataPacket.DataPayload)
	if !hmac.Equal(macComputed, macReceivedCopy) {
		err = errors.New("providedMac does not match computedMac")
		log.Println(err)
		return nil, nil, nil, err
	}

	// unblind
	nextAHDR, err := unblind(BlindedCopy, sharedKey, dataPacket.CHDR.IVorEXP)
	if err != nil {
		return nil, nil, nil, err
	}

	// remove1Layer
	nextOnion, err := crypto.DEC(sharedKey, dataPacket.CHDR.IVorEXP, OnionCopy, lastLayer)
	if err != nil {
		log.Println(err)
		log.Println("issue when removing an onion layer")
		return nil, nil, nil, err
	}

	// mutateIV
	nextIV, err := crypto.PRP(sharedKey, dataPacket.CHDR.IVorEXP)
	if err != nil {
		log.Println(err)
		log.Println("issue when mutating the IV")
		return nil, nil, nil, err
	}

	nextCHDR := core.CHDR{
		Type:    dataPacket.CHDR.Type,
		Hops:    dataPacket.CHDR.Hops,
		IVorEXP: nextIV,
	}

	nextDataPacket := core.DataPacket{
		CHDR:        nextCHDR,
		AHDR:        core.BytesToAHDR(nextAHDR),
		DataPayload: nextOnion,
	}
	nextRawDataPacket = core.DataPacketToBytes(nextDataPacket)

	return nextRawDataPacket, R, sharedKey, nil
}

// addLayer is similar from removeLayer. Could try to use a lambda for that function between ENC and DEC
// and merge them. But the MAC call is different (onion vs nil) and
// notably, the wasPadding was changed to false, so now addLayer assumes it is not used by the resolver for encoding! (as said resolver must pad)
func (n *Node) addLayer(rawDataPacket []byte) (nextRawDataPacket []byte, R []byte, err error) {
	dataPacket := core.BytesToDataPacket(rawDataPacket)

	decryptedFS, err := decryptAndCheckFS(n.secretKey, dataPacket.AHDR.FS)
	if err != nil {
		log.Println("Error while decrypting the FS")
		return nil, nil, err
	}
	sharedKey := decryptedFS.SharedKey
	R = decryptedFS.Routing

	// Check the mac

	// For some reason (GC?), calling MAC, change my local MacValue. So I'm using this trick to force a valid comparison.
	macReceivedCopy := make([]byte, len(dataPacket.AHDR.Mac))
	copy(macReceivedCopy, dataPacket.AHDR.Mac)

	// Same issue the Onion also get changed, here by the MAC() and on the lhs := append again...
	OnionCopy := make([]byte, len(dataPacket.DataPayload))
	copy(OnionCopy, dataPacket.DataPayload)

	// Same issue the Blinded also get changed, here by the MAC() and on the lhs := append again...
	BlindedCopy := make([]byte, len(dataPacket.AHDR.Blinded))
	copy(BlindedCopy, dataPacket.AHDR.Blinded)

	// I solved the mystery with the above lines, but if I want to investigate more, a curious impact of MAC is that the 16 first bytes of Blinded becomes the 16 bytes of MacReceived
	// Checking the mac must only include Onion on the forwardPath. i.e. when removing a layer, not when addingLayer
	macComputed := crypto.MAC(sharedKey, dataPacket.CHDR.IVorEXP, dataPacket.AHDR.FS, dataPacket.AHDR.Blinded, nil)
	if !hmac.Equal(macComputed, macReceivedCopy) {
		err = errors.New("providedMac does not match computedMac")
		log.Println(err)
		return nil, nil, err
	}

	// unblind
	nextAHDR, err := unblind(BlindedCopy, sharedKey, dataPacket.CHDR.IVorEXP)
	if err != nil {
		return nil, nil, err
	}

	// remove1Layer
	nextOnion, err := crypto.ENC(sharedKey, dataPacket.CHDR.IVorEXP, OnionCopy, core.DataPaddingFactor, false)
	if err != nil {
		log.Println(err)
		log.Println("issue when removing an onion layer")
		return nil, nil, err
	}

	// mutateIV
	nextIV, err := crypto.PRP(sharedKey, dataPacket.CHDR.IVorEXP)
	if err != nil {
		log.Println(err)
		log.Println("issue when mutating the IV")
		return nil, nil, err
	}

	nextCHDR := core.CHDR{
		Type:    dataPacket.CHDR.Type,
		Hops:    dataPacket.CHDR.Hops,
		IVorEXP: nextIV,
	}

	nextDataPacket := core.DataPacket{
		CHDR:        nextCHDR,
		AHDR:        core.BytesToAHDR(nextAHDR),
		DataPayload: nextOnion,
	}
	nextRawDataPacket = core.DataPacketToBytes(nextDataPacket)

	return nextRawDataPacket, R, nil
}

// decryptAndCheckFS is roughly equivalent to FS_OPEN from the HORNET paper, but also includes the expiration check
// which is always done when decrypting an FS.
func decryptAndCheckFS(nodeSecretKey, FS []byte) (core.DecryptedFS, error) {
	rawDecryptedFS, err := crypto.PRPInverse(nodeSecretKey, FS)
	if err != nil {
		log.Println("Couldn't decrypt the FS")
		return core.DecryptedFS{}, err
	}
	//debugPrintDecryptedFS(decryptedFS, "removeLayer")
	decryptedFS := core.BytesToFS(rawDecryptedFS)

	if isEXPExpired(decryptedFS.EXP) {
		err = errors.New("packet time expired")
		log.Println(err)
		return core.DecryptedFS{}, err
	}

	return decryptedFS, nil
}

// unblind performs an operation opposite to blind and allows node to recover the next anonymous header
func unblind(Blinded, sharedKey, IV []byte) ([]byte, error) {
	lhs := append(Blinded, make([]byte, core.BlockLength)...)
	rhs, err := crypto.PRG(append(sharedKey, IV...))
	if err != nil {
		log.Println(err)
		log.Println("issue when generating the PRG to unblind")
		return nil, err
	}
	rhs = rhs[:(int(core.MaxPathLength))*core.BlockLength+0] // +0 is +b in taranet, and stands for the size of the control bits and expiration time. I don't use them here
	// If I follow HORNET indices instead of TARANET, it's indeed just the easy fix (but confirmed by analysis as correct): blinded size is (r-1)c, which gets concatenated with 1c. So rhs should be len = rc
	nextAHDR, err := xor(lhs, rhs)
	if err != nil {
		log.Println("Couldn't xor when removing layer")
		return nil, err
	}
	return nextAHDR, nil
}

// blind performs an operation opposite to unblind and allows the requester to prepare the anonymous headers through layers of encryption.
func blind(FS, mac, blinded, sharedKey, IV []byte) ([]byte, error) {
	lhs := append(FS, mac...)
	lhs = append(lhs, blinded[:core.BlockLength*(int(core.MaxPathLength)-2)]...)
	rhs, err := crypto.PRG(append(sharedKey, IV...))
	if err != nil {
		log.Println("Couldn't generate static randomness")
		return nil, err
	}
	// do I assume there was an error in TARANET paper, and change -2 to -1? No, instead, apply the -2 only to blinded, before appending to FS and mac
	// near confirmed that TARANET -1 is because of math notation, and in programming terms, I don't need to add the -1 on those slice end-indices
	nextBlinded, err := xor(lhs, rhs[:core.BlockLength*(int(core.MaxPathLength)-1)])
	if err != nil {
		log.Println("Couldn't create the next iteration of blinded for the forward onion")
		return nil, err
	}
	return nextBlinded, nil
}
