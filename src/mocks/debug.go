package mocks

import (
	"encoding/binary"
	"fmt"
	"github.com/scionproto/scion/pkg/snet"
	"main.go/core"
)

// This file provides some print function for packets and onion with the intent of efficiently and quickly comparing contents
// Full bytes are not printed (a couple of bytes per item are enough), and human representation is not guaranteed either.

func debugPrintPacket(pkt snet.Packet, where string) {
	/*fmt.Println()
	fmt.Println(where)
	fmt.Print("Source: ")
	fmt.Println(pkt.Source)
	fmt.Print("Destination: ")
	fmt.Println(pkt.Destination)
	fmt.Print("Path: ")
	fmt.Println(pkt.Path)
	fmt.Print("Payload: ")*/
	//debugPrintPayload(pkt.Payload, where)
}

/* Notably with a path length of 2, there should be:
 A ----0---> B ----1---> C (2 = pt)
A creates 1 = enc(pt) and 0 = enc(1) = enc(enc(pt))
B does dec(0) = 1
C does dec(1) = dec(dec(0)) = pt
To check, A should print pt, 1, 0
B should print 0 and 1
C should print 1 and pt
*/

func debugPrintPayload(payload snet.Payload, where string) {
	fmt.Println()
	fmt.Printf("Payload %s, next two lines should be identical\n", where)
	//fmt.Println(payload)
	pld := payload.(snet.UDPPayload).Payload
	//fmt.Println(pld)
	IV := pld[2:core.CHDRLength]
	AHDR := pld[core.CHDRLength : core.CHDRLength+core.AHDRLength]
	FS := AHDR[:core.FSLength]
	MacReceived := AHDR[core.FSLength : core.FSLength+core.SecurityParameter]
	Blinded := AHDR[core.FSLength+core.SecurityParameter:]
	Onion := pld[core.CHDRLength+core.AHDRLength:]
	fmt.Print("IV: ")
	fmt.Println(IV[0:4])
	//fmt.Print("AHDR: ")
	//fmt.Println(AHDR[0:4])
	fmt.Print("FS: ")
	fmt.Println(FS[0:4])
	fmt.Print("MacReceived: ")
	fmt.Println(MacReceived[0:4])
	fmt.Print("Blinded: ")
	fmt.Println(Blinded[0:4])
	fmt.Print("Onion: ")
	fmt.Println(Onion[0:4])
}

func debugPrintDecryptedFS(FS []byte, where string) {
	fmt.Println()
	fmt.Printf("Decrypted FS in %v\n", where)
	R := FS[core.RoutingIndex:core.EXPIndex]
	EXP := FS[core.EXPIndex:core.SharedKeyIndex]
	EXPint := int64(binary.BigEndian.Uint64(EXP))
	sharedKey := FS[core.SharedKeyIndex:]

	fmt.Print("R: ")
	fmt.Println(R[0:4])
	fmt.Print("EXP: ")
	fmt.Println(EXPint)
	fmt.Print("sharedKey: ")
	fmt.Println(sharedKey[0:4])
	fmt.Println()
}
