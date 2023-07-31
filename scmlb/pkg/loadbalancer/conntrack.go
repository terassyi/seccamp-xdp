package loadbalancer

import (
	"net/netip"
	"time"

	"github.com/terassyi/seccamp-xdp/scmlb/pkg/protocols"
)

type ConntrackEntry struct {
	SrcAddr   netip.Addr
	DstAddr   netip.Addr
	SrcPort   uint32
	DstPort   uint32
	Protocol  protocols.TransportProtocol
	State     ConnectionState
	Timestamp time.Time
	BackendId uint32
	Counter   uint64
}

type conntrackKey struct {
	SrcAddr  uint32
	DstAddr  uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint32
}

type conntrackInfo struct {
	Id         uint32
	Index      uint32
	Status     uint8
	SrcMacAddr [6]uint8
	Counter    uint64
}

type ConnectionState uint8

const (
	ConnectionStateNotTcp      = ConnectionState(0)
	ConnectionStateOpening     = ConnectionState(1)
	ConnectionStateEstablished = ConnectionState(2)
	ConnectionStateClosing     = ConnectionState(3)
	ConnectionStateClosed      = ConnectionState(4)
)

func (c ConnectionState) String() string {
	switch c {
	case ConnectionStateNotTcp:
		return "NotTCP"
	case ConnectionStateOpening:
		return "Opening"
	case ConnectionStateEstablished:
		return "Established"
	case ConnectionStateClosing:
		return "Closing"
	case ConnectionStateClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}
