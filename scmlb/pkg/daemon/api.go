package daemon

import (
	"context"
	"fmt"

	"github.com/terassyi/seccamp-xdp/scmlb/pkg/rpc"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/slog"
	"google.golang.org/protobuf/types/known/emptypb"
)

// このファイルでは CLI(scmlb コマンド) と通信するための gRPC API を定義しています。
// API 定義は protobuf/scmlb.proto を参照してください

func (d *Daemon) Health(ctx context.Context, in *rpc.HealthRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// scmlbd の統計情報を返す API を定義しています。
func (d *Daemon) Stat(ctx context.Context, in *rpc.StatRequest) (*rpc.StatResponse, error) {

	// upstream interface
	iface, err := netlink.LinkByName(d.upstream)
	if err != nil {
		d.logger.ErrorCtx(ctx, "interface is not found", err, slog.String("name", d.upstream))
		return nil, fmt.Errorf("interface not found")
	}

	// パケットカウンタの値を eBPF マップから取得します
	res, err := d.counter.Get(ctx)
	if err != nil {
		d.logger.ErrorCtx(ctx, "failed to get counter infomration from eBPF map", err)
		return nil, err
	}

	d.logger.InfoCtx(ctx, "get stat",
		slog.String("interface", iface.Attrs().Name),
		slog.Int("tcp", int(res.Tcp)),
		slog.Int("udp", int(res.Udp)),
		slog.Int("icmp", int(res.Icmp)),
	)
	upstreamIface := rpc.Interface{
		Name:  iface.Attrs().Name,
		Index: int32(iface.Attrs().Index),
		Counter: &rpc.PacketCounter{
			Icmp: int32(res.Icmp),
			Tcp:  int32(res.Tcp),
			Udp:  int32(res.Udp),
		},
	}

	return &rpc.StatResponse{
		Ifaces: []*rpc.Interface{
			&upstreamIface,
		},
	}, nil
}
