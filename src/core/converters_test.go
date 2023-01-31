package core

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSplitMergeCHDR(t *testing.T) {
	rawCHDR := make([]byte, CHDRLength)
	_, err := rand.Read(rawCHDR)
	if err != nil {
		t.Fatalf("Couldn't read randomness")
	}

	CHDR := bytesToCHDR(rawCHDR)

	result := CHDRToBytes(CHDR)

	if !bytes.Equal(rawCHDR, result) {
		t.Fatalf("CHDR conversions not equivalent")
	}
}

func TestSplitMergeAHDR(t *testing.T) {
	rawAHDR := make([]byte, AHDRLength)
	_, err := rand.Read(rawAHDR)
	if err != nil {
		t.Fatalf("Couldn't read randomness")
	}

	AHDR := BytesToAHDR(rawAHDR)

	result := AHDRToBytes(AHDR)

	if !bytes.Equal(rawAHDR, result) {
		t.Fatalf("AHDR conversions not equivalent")
	}
}

func TestSplitMergeDataPacket(t *testing.T) {
	rawDataPacket := make([]byte, CHDRLength+AHDRLength+400)
	_, err := rand.Read(rawDataPacket)
	if err != nil {
		t.Fatalf("Couldn't read randomness")
	}

	dataPacket := BytesToDataPacket(rawDataPacket)

	result := DataPacketToBytes(dataPacket)

	if !bytes.Equal(rawDataPacket, result) {
		t.Fatalf("DataPacket conversions not equivalent")
	}
}

func TestSplitMergeSetupPacket(t *testing.T) {
	rawSetupPacket := make([]byte, CHDRLength+64+2*FSPayloadLength)
	_, err := rand.Read(rawSetupPacket)
	if err != nil {
		t.Fatalf("Couldn't read randomness")
	}

	setupPacket := BytesToSetupPacket(rawSetupPacket)

	result := SetupPacketToBytes(setupPacket)

	if !bytes.Equal(rawSetupPacket, result) {
		t.Fatalf("SetupPacket conversions not equivalent")
	}
}
