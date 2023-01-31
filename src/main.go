package main

import (
	"github.com/jessevdk/go-flags"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"log"
	"main.go/node"
	"os"
	"strconv"
	"strings"
)

type Options struct {
	NodeType   string `long:"node" description:"Must be either requester, resolver or relay" required:"true"`
	Onioning   bool   `long:"onion" description:"True to activate onion encryption and routing"`
	Address    string `long:"address" description:"Full SCION address of the local node, must follow the format ISD,AS,Host such as 1,3,5.0.0.7" required:"true"`
	Port       int    `long:"port" description:"Port number of the ???"`
	Nameserver string `long:"ns" description:"If node is resolver, then this field must be specified with the non-SCION address of the CoreDNS nameserver. Must also include the port following this schema 127.0.0.1:1053 This is also the default value" default:"127.0.0.1:1053"`

	// TODO maybe add required = true to the two below? Or use a default value for test purposes?
	ScionDAddress            string `long:"sciond" description:"SCIOND address"`
	DispatcherSocket         string `long:"dispatcher-socket" description:"dispatcher socket"`
	RecursiveResolverAddress string `long:"address" description:"If node is requester, full SCION address of the recursive resolver, must follow the format ISD,AS,Host such as 1,3,5.0.0.7"`
}

func main() {
	var options Options
	args, err := flags.Parse(&options)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	if len(args) != 0 {
		log.Println("No args expected")
		os.Exit(1)
	}
	LocalSCIONAddress := processAddress(options.Address)
	if options.NodeType == "requester" {
		RecurResolverSCIONAddres := processAddress(options.RecursiveResolverAddress)
		node.RunRequesterNode(options.Onioning, LocalSCIONAddress, RecurResolverSCIONAddres, options.ScionDAddress, options.DispatcherSocket)
	} else if options.NodeType == "relay" {
		node.RunRelayNode(options.Onioning, LocalSCIONAddress, options.ScionDAddress, options.DispatcherSocket)
	} else if options.NodeType == "resolver" {
		node.RunRecursiveResolverNode(options.Onioning, LocalSCIONAddress, options.Nameserver, options.ScionDAddress, options.DispatcherSocket)
	} else {
		log.Println("Node type must be either requester, resolver or relay")
		os.Exit(1)
	}
}

// processAddress transform a string formatted as "ISD,AS,Host" such as "1,3,5.0.0.7" into the corresponding SCION structure.
func processAddress(address string) snet.SCIONAddress {
	addresses := strings.Split(address, ",")
	if len(addresses) != 3 {
		log.Println("SCIONAddress malformed")
		os.Exit(1)
	}
	isd, err := strconv.Atoi(addresses[0])
	if err != nil {
		log.Println("ISD should parse as a uint16")
		log.Println(err)
		os.Exit(1)
	}
	as, err := strconv.Atoi(addresses[1])
	if err != nil {
		log.Println("AS should parse as a uint64")
		log.Println(err)
		os.Exit(1)
	}
	ia, err := addr.IAFrom(addr.ISD(isd), addr.AS(as))
	if err != nil {
		log.Println("Err when decoding the IA part of the address")
		log.Println(err)
		os.Exit(1)
	}
	host := addr.HostFromIPStr(addresses[2])
	SCIONAddress := snet.SCIONAddress{
		IA:   ia,
		Host: host,
	}
	return SCIONAddress
}
