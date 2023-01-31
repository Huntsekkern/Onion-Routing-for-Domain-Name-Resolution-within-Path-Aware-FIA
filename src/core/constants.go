package core

const (
	// SecurityParameter is k in HORNET in bits in the paper, hence divided by 8 here = 16. Is amongst other the size of the MAC.
	SecurityParameter = 128 / 8
	// FSLength is |FS| in HORNET in bits in the paper, hence divided by 8 = 32
	FSLength = 256 / 8
	// BlockLength is c in HORNET, = 48 bytes in the example.
	BlockLength = SecurityParameter + FSLength
	// MaxPathLength is r in HORNET. Usually need to be casted to int to be used, but appears as a single byte in the packets
	MaxPathLength uint8 = 7
	// DataPaddingFactor in bytes. Used for padding
	DataPaddingFactor = 64

	SetupType        uint8 = 1
	DataTypeForward  uint8 = 3
	DataTypeBackward uint8 = 4

	CHDRLength             = 2 + SecurityParameter
	AHDRLength      uint16 = BlockLength * uint16(MaxPathLength)
	FSPayloadLength        = BlockLength * int(MaxPathLength)

	// FS Content
	RoutingIndex    = 0
	RoutingLength   = 8
	EXPIndex        = RoutingIndex + RoutingLength
	EXPLength       = 8 // time is an int64, in UNIX-format
	SharedKeyIndex  = EXPIndex + EXPLength
	SharedKeyLength = SecurityParameter

	SessionDurationSeconds = 30
)

/*
Thoughts about FS size vs routing segment.
So half of the FS is for the mac. ExpTime is an int64, so 8 bytes.
So I literally only have 8 bytes for the routing info.
Seems tricky to fit everything in 8 bytes, but I'll try. If not, will have to expand the FS size, causing a bunch of shifts everywhere...
Theoretically, from my conversation with Mathias, I could get away with only the egress and ingress interface IDs, at which point those are 2 uint16.
So I would still have 2 more uint16 if needed for some ISD-AS information if needed. Okay, maybe it's doable.
*/
