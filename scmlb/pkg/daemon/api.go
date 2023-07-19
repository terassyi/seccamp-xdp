package daemon

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/terassyi/seccamp-xdp/scmlb/pkg/firewall"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/protocols"
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

func (d *Daemon) FireWallRuleSet(ctx context.Context, in *rpc.FireWallRuleSetRqeust) (*emptypb.Empty, error) {

	proto, err := protocols.NewTransportProtocol(uint32(in.Rule.Protocol))
	if err != nil {
		return nil, err
	}

	prefix, err := netip.ParsePrefix(in.Rule.Prefix)
	if err != nil {
		return nil, err
	}

	rule := &firewall.FWRule{
		Prefix:   prefix,
		FromPort: uint32(in.Rule.FromPort),
		ToPort:   uint32(in.Rule.ToPort),
		Protocol: proto,
	}

	d.logger.InfoCtx(ctx, "add fire wall rule", slog.Any("rule", rule))
	if err := d.fw.Set(rule); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (d *Daemon) FireWallRuleGet(ctx context.Context, in *rpc.FireWallRuleGetRequest) (*rpc.FireWallRuleGetResponse, error) {

	rules := make([]*rpc.FireWallRule, 0)

	d.logger.DebugCtx(ctx, "get fire wall rules")
	rr, err := d.fw.Get()
	if err != nil {
		d.logger.ErrorCtx(ctx, "failed to get rule", err)
		return nil, err
	}
	for _, r := range rr {
		rules = append(rules, &rpc.FireWallRule{
			Id:       int32(r.Id),
			Prefix:   r.Prefix.String(),
			FromPort: int32(r.FromPort),
			ToPort:   int32(r.ToPort),
			Protocol: int32(r.Protocol),
			Count:    int64(r.Count),
		})
	}

	return &rpc.FireWallRuleGetResponse{
		Rules: rules,
	}, nil
}

func (d *Daemon) FireWallRuleDelete(ctx context.Context, in *rpc.FireWallRuleDeleteRequest) (*emptypb.Empty, error) {

	d.logger.InfoCtx(ctx, "delete fire wall rule", slog.Any("id", in.Id))
	if err := d.fw.Delete(uint32(in.Id)); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
