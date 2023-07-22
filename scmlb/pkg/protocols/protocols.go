package protocols

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
)

type TransportProtocol uint32

const (
	TransportProtocolAny  TransportProtocol = TransportProtocol(0)
	TransportProtocolIcmp TransportProtocol = TransportProtocol(constants.PROTOCOL_ICMP)
	TransportProtocolTcp  TransportProtocol = TransportProtocol(constants.PROTOCOL_TCP)
	TransportProtocolUdp  TransportProtocol = TransportProtocol(constants.PROTOCOL_UDP)
)

func NewTransportProtocol(proto uint32) (TransportProtocol, error) {
	switch proto {
	case 0:
		return TransportProtocolAny, nil
	case constants.PROTOCOL_ICMP:
		return TransportProtocolIcmp, nil
	case constants.PROTOCOL_TCP:
		return TransportProtocolTcp, nil
	case constants.PROTOCOL_UDP:
		return TransportProtocolUdp, nil
	default:
		return TransportProtocol(255), fmt.Errorf("unknown transport protocol: %d", proto)
	}
}

func TransportProtocolFromString(proto string) (TransportProtocol, error) {
	switch proto {
	case "any":
		return TransportProtocolAny, nil
	case "icmp":
		return TransportProtocolIcmp, nil
	case "tcp":
		return TransportProtocolTcp, nil
	case "udp":
		return TransportProtocolUdp, nil
	default:
		return TransportProtocol(255), fmt.Errorf("unknown transport protocol: %s", proto)
	}
}

func (p TransportProtocol) String() string {
	switch p {
	case TransportProtocolAny:
		return "any"
	case TransportProtocolIcmp:
		return "icmp"
	case TransportProtocolTcp:
		return "tcp"
	case TransportProtocolUdp:
		return "udp"
	default:
		return fmt.Sprintf("unknown(%d)", p)
	}
}

type TcpFlag uint8

const (
	TcpFlagFin TcpFlag = TcpFlag(1)
	TcpFlagSyn TcpFlag = TcpFlag(2)
	TcpFlagRst TcpFlag = TcpFlag(4)
	TcpFlagPsh TcpFlag = TcpFlag(8)
	TcpFlagAck TcpFlag = TcpFlag(6)
	TcpFlagUrg TcpFlag = TcpFlag(32)
	TcpFlagEce TcpFlag = TcpFlag(64)
	TcpFlagCwr TcpFlag = TcpFlag(28)
)

func NewTcpFlag(v uint8) (TcpFlag, error) {
	switch v {
	case 1:
		return TcpFlagFin, nil
	case 2:
		return TcpFlagSyn, nil
	case 4:
		return TcpFlagRst, nil
	case 8:
		return TcpFlagPsh, nil
	case 16:
		return TcpFlagAck, nil
	case 32:
		return TcpFlagUrg, nil
	case 64:
		return TcpFlagEce, nil
	case 128:
		return TcpFlagCwr, nil
	default:
		return TcpFlag(0), fmt.Errorf("invalid tcp flag: %d", v)
	}
}

func TcpFlagFromString(s string) (TcpFlag, error) {
	switch s {
	case "fin", "FIN", "Fin":
		return TcpFlagFin, nil
	case "syn", "SYN", "Syn":
		return TcpFlagSyn, nil
	case "rst", "RST", "Rst":
		return TcpFlagRst, nil
	case "psh", "PSH", "Psh":
		return TcpFlagPsh, nil
	case "ack", "ACK", "Ack":
		return TcpFlagAck, nil
	case "urg", "URG", "Urg":
		return TcpFlagUrg, nil
	case "ece", "ECE", "Ece":
		return TcpFlagEce, nil
	case "cwr", "CWR", "Cwr":
		return TcpFlagCwr, nil
	default:
		return TcpFlag(0), fmt.Errorf("invalid tcp flag: %s", s)
	}
}

func (f TcpFlag) String() string {
	switch f {
	case TcpFlagFin:
		return "fin"
	case TcpFlagSyn:
		return "syn"
	case TcpFlagRst:
		return "rst"
	case TcpFlagPsh:
		return "psh"
	case TcpFlagAck:
		return "ack"
	case TcpFlagUrg:
		return "urg"
	case TcpFlagEce:
		return "ece"
	case TcpFlagCwr:
		return "cwr"
	default:
		return "unknown"
	}
}

func IpAddrFromLe(v uint32) (netip.Addr, error) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid ip address value %d", v)
	}
	return addr, nil
}
