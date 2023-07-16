package component

import "github.com/vishvananda/netlink"

type XdpComponent interface {
	Load(iface netlink.Link) error
	Close() error
	Name() string
}
