package main

import (
	"fmt"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func (s *Server) Dial(network, address string) (net.Conn, error) {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}

	remote := tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(addrPort.Addr().AsSlice()),
		Port: addrPort.Port(),
	}

	var networkProtocol tcpip.NetworkProtocolNumber

	if addrPort.Addr().Is4() {
		networkProtocol = header.IPv4ProtocolNumber
	} else {
		networkProtocol = header.IPv6ProtocolNumber
	}

	if network == "tcp" {
		return gonet.DialTCP(s.stack, remote, networkProtocol)
	}

	if network == "udp" {
		return gonet.DialUDP(s.stack, nil, &remote, networkProtocol)
	}

	return nil, fmt.Errorf("unsupported network: %s", network)
}
