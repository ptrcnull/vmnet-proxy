package main

import (
	"fmt"
	"net"
	"vmnet-proxy/pkg/vmnet"

	"github.com/rs/zerolog/log"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type Server struct {
	*vmnet.VMNet

	linkHost    tcpip.LinkAddress
	linkGateway tcpip.LinkAddress

	protoHost    tcpip.AddressWithPrefix
	protoGateway tcpip.Address

	dispatcher stack.NetworkDispatcher
	stack      *stack.Stack
}

func NewServer(hostIface string, linkHostStr string, protoHostStr string, protoGatewayStr string) (*Server, error) {
	// convert addresses
	linkHost, err := tcpip.ParseMACAddress(linkHostStr)
	if err != nil {
		return nil, fmt.Errorf("parse mac address: %w", err)
	}
	protoHostIP, protoHostNet, err := net.ParseCIDR(protoHostStr)
	if err != nil {
		return nil, fmt.Errorf("parse host ip: %w", err)
	}
	prefixLen, _ := protoHostNet.Mask.Size()

	protoHost := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice(protoHostIP.To4()),
		PrefixLen: prefixLen,
	}

	protoGatewayAddr := net.ParseIP(protoGatewayStr)
	if protoGatewayAddr == nil {
		return nil, fmt.Errorf("invalid gateway IP: %s", protoGatewayStr)
	}
	protoGateway := tcpip.AddrFromSlice(protoGatewayAddr.To4())

	// start vmnet
	vmn := vmnet.New()
	if err := vmn.Start(hostIface); err != nil {
		return nil, err
	}

	// create server
	server := &Server{
		VMNet: vmn,

		linkHost:    linkHost,
		linkGateway: header.EthernetBroadcastAddress,

		protoHost:    protoHost,
		protoGateway: protoGateway,
	}

	// create stack
	st := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})
	if err := st.CreateNIC(1, server); err != nil {
		panic(err)
	}

	st.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: protoHost,
	}, stack.AddressProperties{})
	st.SetRouteTable([]tcpip.Route{
		{
			Destination: protoHost.Subnet(),
			NIC:         1,
		},
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         1,
			Gateway:     protoGateway,
		},
	})
	server.stack = st

	return server, nil
}

func (s *Server) Shutdown() {
	s.stack.Close()
	s.VMNet.Stop()
}

// ARPHardwareType implements stack.LinkEndpoint.
func (s *Server) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}

// AddHeader implements stack.LinkEndpoint.
func (s *Server) AddHeader(pkt *stack.PacketBuffer) {
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		Type:    pkt.NetworkProtocolNumber,
		SrcAddr: pkt.EgressRoute.LocalLinkAddress,
		DstAddr: pkt.EgressRoute.RemoteLinkAddress,
	})
}

// ParseHeader implements stack.LinkEndpoint.
func (s *Server) ParseHeader(pkt *stack.PacketBuffer) bool {
	hdrBytes, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	if !ok {
		return false
	}
	hdr := header.Ethernet(hdrBytes)
	pkt.NetworkProtocolNumber = hdr.Type()
	return true
}

// Attach implements stack.LinkEndpoint.
func (s *Server) Attach(dispatcher stack.NetworkDispatcher) {
	log.Info().Msg("attached dispatcher")
	s.dispatcher = dispatcher
}

// Capabilities implements stack.LinkEndpoint.
func (r *Server) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityResolutionRequired
}

// Close implements stack.LinkEndpoint.
func (s *Server) Close() {}

// IsAttached implements stack.LinkEndpoint.
func (s *Server) IsAttached() bool {
	return s.dispatcher != nil
}

// LinkAddress implements stack.LinkEndpoint.
func (s *Server) LinkAddress() tcpip.LinkAddress {
	return s.linkHost
}

// MTU implements stack.LinkEndpoint.
func (s *Server) MTU() uint32 {
	return 1500
}

// MaxHeaderLength implements stack.LinkEndpoint.
func (s *Server) MaxHeaderLength() uint16 {
	return header.EthernetMinimumSize
}

// SetLinkAddress implements stack.LinkEndpoint.
func (s *Server) SetLinkAddress(addr tcpip.LinkAddress) {
	s.linkHost = addr
}

// SetMTU implements stack.LinkEndpoint.
func (s *Server) SetMTU(mtu uint32) {}

// SetOnCloseAction implements stack.LinkEndpoint.
func (s *Server) SetOnCloseAction(func()) {}

// Wait implements stack.LinkEndpoint.
func (s *Server) Wait() {}

// WritePackets implements stack.LinkEndpoint.
func (s *Server) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	var n int
	for _, pkt := range pkts.AsSlice() {
		buf := pkt.ToBuffer()
		data := buf.Flatten()

		ether := header.Ethernet(data)
		PrintPacket("put", ether)

		_, err := s.Write(data)
		if err != nil {
			return n, &tcpip.ErrNotConnected{}
		}
		n++
	}
	return n, nil
}

func (r *Server) Loop() {
	for {
		bytes := make([]byte, r.MaxPacketSize)
		bytesLen, err := r.Read(bytes)
		if err != nil {
			log.Error().Msgf("error while reading from vmnet: %s", err.Error())
			continue
		}

		bytes = bytes[:bytesLen]

		r.HandlePacket(bytes)
	}
}

func (s *Server) HandlePacket(data []byte) {
	ether := header.Ethernet(data)

	if ether.DestinationAddress() != s.linkHost && ether.DestinationAddress() != header.EthernetBroadcastAddress {
		// who the fuck are you
		return
	}

	PrintPacket("got", ether)

	payload := ether[header.EthernetMinimumSize:]

	buf := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(payload),
	})

	if s.dispatcher != nil {
		s.dispatcher.DeliverNetworkPacket(ether.Type(), buf)
	}
}

func PrintPacket(what string, ether header.Ethernet) {
	defer recover()
	PrintPacketUnsafe(what, ether)
}

func PrintPacketUnsafe(what string, ether header.Ethernet) {
	log.Trace().Msgf(
		"%s Ethernet %d (%d bytes) from %s to %s",
		what, ether.Type(), len(ether),
		ether.SourceAddress().String(),
		ether.DestinationAddress().String(),
	)

	payload := ether[header.EthernetMinimumSize:]

	switch ether.Type() {
	case header.ARPProtocolNumber:
		arp := header.ARP(payload)
		var typ string
		if arp.Op() == header.ARPRequest {
			typ = "Request"
		} else {
			typ = "Reply"
		}
		linkSrc := tcpip.LinkAddress(arp.HardwareAddressSender())
		linkDst := tcpip.LinkAddress(arp.HardwareAddressTarget())
		protoSrc := tcpip.AddrFromSlice(arp.ProtocolAddressSender())
		protoDst := tcpip.AddrFromSlice(arp.ProtocolAddressTarget())
		log.Trace().Msgf("\tARP %s from %s (%s) to %s (%s)", typ, protoSrc, linkSrc, protoDst, linkDst)

	case header.IPv4ProtocolNumber:
		ipv4 := header.IPv4(payload)
		log.Trace().Msgf("\tIPv4 %d from %s to %s", ipv4.TransportProtocol(), ipv4.SourceAddress().String(), ipv4.DestinationAddress().String())
		payload := ipv4[header.IPv4MinimumSize:]
		switch ipv4.TransportProtocol() {
		case header.ICMPv4ProtocolNumber:
			icmp := header.ICMPv4(payload)
			size := header.ICMPv4MinimumSize + len(icmp.Payload())
			log.Trace().Msgf("\t\tICMPv4: %d bytes from %s: icmp_seq=%d ttl=%d", size, ipv4.SourceAddress(), icmp.Sequence(), ipv4.TTL())
		case header.UDPProtocolNumber:
			udp := header.UDP(payload)
			log.Trace().Msgf("\t\tUDP from port %d to port %d: %d bytes", udp.SourcePort(), udp.DestinationPort(), udp.Length())
			if udp.DestinationPort() == 4444 {
				log.Trace().Msgf("\t\t\twoof! %s", string(udp.Payload()))
			}
		case header.TCPProtocolNumber:
			tcp := header.TCP(payload)
			log.Trace().Msgf("\t\tTCP %s from %d to %d", tcp.Flags().String(), tcp.SourcePort(), tcp.DestinationPort())
		}
	case header.IPv6ProtocolNumber:
		ipv6 := header.IPv6(payload)
		log.Trace().Msgf("\tIPv6 %d from %s to %s", ipv6.TransportProtocol(), ipv6.SourceAddress().String(), ipv6.DestinationAddress().String())
	}
}
