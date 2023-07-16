package counter

import (
	"context"

	"github.com/cilium/ebpf"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/vishvananda/netlink"
)

type Counter struct {
	iface netlink.Link
	p     *ebpf.Program
	m     *ebpf.Map
}

type CounterResult struct {
	Icmp uint32
	Tcp  uint32
	Udp  uint32
}

func New(name string, p *ebpf.Program, m *ebpf.Map) (*Counter, error) {
	iface, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}

	return &Counter{
		iface: iface,
		p:     p,
		m:     m,
	}, nil
}

func (c *Counter) Get(ctx context.Context) (CounterResult, error) {

	var (
		icmpCount uint32
		tcpCount  uint32
		udpCounte uint32
	)

	if err := c.m.Lookup(constants.PROTOCOL_ICMP, &icmpCount); err != nil {
		return CounterResult{}, nil
	}
	if err := c.m.Lookup(constants.PROTOCOL_TCP, &tcpCount); err != nil {
		return CounterResult{}, nil
	}
	if err := c.m.Lookup(constants.PROTOCOL_UDP, &udpCounte); err != nil {
		return CounterResult{}, nil
	}

	return CounterResult{
		Icmp: icmpCount,
		Tcp:  tcpCount,
		Udp:  udpCounte,
	}, nil
}
