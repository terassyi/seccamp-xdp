package protocols

import (
	"fmt"

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
