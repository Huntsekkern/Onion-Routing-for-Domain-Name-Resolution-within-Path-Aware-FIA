# Organisation

The overall idea in terms of levels hierarchy is:
Network > Nodes > Protocol > Crypto > Core. \
But package-wise, network, node and protocol are bundled together in Node.


# Nomenclature

Regarding nodes names: \
requester = stub resolver = source \
relay = router = intermediate relay \
resolver = recursive resolver = destination.

The naming of the packet content is definitely problematic as there are many usages of the terms packet and payload,
and this already comes from SCION nomenclature.

The structure goes like that (combination of SCION nomenclature and my own names that I try to stick to in the code)

snet.Packet [SCION packet] \
has a \
PacketInfo field \
which has a \
Payload field. \
\
That Payload field is an interface \
which I'm using with \
snet.UDPPayload. \
\
snet.UDPPayload \
has a \
Payload field \
which is a []byte. \
\
In that Payload field, I'm storing what HORNET calls a packet. \
I'll explicitly call those dataPacket or setupPacket to differentiate them from snet.Packet. \
And they will have associated struct. \
Those packets will follow the structure from HORNET p.4 \
The payloads in them will be called explicitly sphinxPayload or dataPayload to differentiate them from snet.Packet.Payload and from snet.UDPPayload.Payload.
\
 So yes, overall, there will be a Packet, holding a Payload which is called a (data)Packet containaing a (data)Payload.
TIHI.

A dataPayload can also be referenced to as an Onion (or O). \
A DNSPayload refers to a non-encrypted dataPayload. Note however that in the forward path, a dataPayload includes both the return header and IV and the DNSPayload.

Sphinx and Setup / SetupPhase are used interchangeably.


# Usage

It has not been tested on a real SCION topology, but the theoretical usage would be
to run one stub resolver (requester) node, some relay nodes, one recursive resolver node, and one CoreDNS server.

Relays, recursive resolver and CoreDNS need to be properly configured, but are then listening.
Stub resolver (requester) waits for user input on the CLI after starting the node. DNS queries are typically expected as input.

The list of flags and their description is available at the top of main.go