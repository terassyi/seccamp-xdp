package daemon

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/terassyi/seccamp-xdp/scmlb/pkg/dosprotector"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/firewall"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/loadbalancer"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/protocols"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/rpc"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/slog"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
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
		Prefix:      prefix,
		FromSrcPort: uint32(in.Rule.FromSrcPort),
		ToSrcPort:   uint32(in.Rule.ToSrcPort),
		FromDstPort: uint32(in.Rule.FromDstPort),
		ToDstPort:   uint32(in.Rule.ToDstPort),
		Protocol:    proto,
	}

	d.logger.InfoCtx(ctx, "add fire wall rule", slog.Any("rule", rule))
	if _, err := d.fw.Set(rule); err != nil {
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
			Id:          int32(r.Id),
			Prefix:      r.Prefix.String(),
			FromSrcPort: int32(r.FromSrcPort),
			ToSrcPort:   int32(r.ToSrcPort),
			FromDstPort: int32(r.FromDstPort),
			ToDstPort:   int32(r.ToDstPort),
			Protocol:    int32(r.Protocol),
			Count:       int64(r.Count),
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

func (d *Daemon) DoSProtectionPolicySet(ctx context.Context, in *rpc.DoSProtectionPolicySetRequest) (*emptypb.Empty, error) {
	protocol, err := protocols.NewTransportProtocol(uint32(in.Policy.Protocol))
	if err != nil {
		return nil, err
	}
	typ, err := protocols.TcpFlagFromString(in.Policy.Type)
	if err != nil {
		return nil, err
	}
	policy := dosprotector.Policy{
		Protocol: protocol,
		Type:     typ,
		Limit:    uint64(in.Policy.Limit),
	}

	d.logger.InfoCtx(ctx, "set new policy", slog.Any("policy", policy))
	if _, err := d.dosProtector.Set(ctx, &policy); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (d *Daemon) DoSProtectionPolicyGet(ctx context.Context, in *rpc.DoSProtectionPolicyGetRequest) (*rpc.DoSProtectionPolicyGetResponse, error) {

	protoPolicies := make([]*rpc.DoSProtectionPolicy, 0)

	d.logger.InfoCtx(ctx, "get DoS protection policies")
	policies, err := d.dosProtector.Get()
	if err != nil {
		return nil, err
	}

	d.logger.DebugCtx(ctx, "policies", slog.Any("policies", policies))

	for _, p := range policies {
		protoPolicies = append(protoPolicies, &rpc.DoSProtectionPolicy{
			Id:       int32(p.Id),
			Protocol: int32(p.Protocol),
			Type:     p.Type.String(),
			Limit:    int64(p.Limit),
			Status:   int32(p.Status),
		})
	}

	return &rpc.DoSProtectionPolicyGetResponse{
		Policies: protoPolicies,
	}, nil
}

func (d *Daemon) DoSProtectionPolicyDelete(ctx context.Context, in *rpc.DoSProtectionPolicyDeleteRequest) (*emptypb.Empty, error) {

	d.logger.InfoCtx(ctx, "delete a DoS protection policy", slog.Int("id", int(in.Id)))
	if err := d.dosProtector.Delete(uint32(in.Id)); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

func (d *Daemon) LoadBalancerSet(ctx context.Context, in *rpc.LoadBalancerSetRequest) (*emptypb.Empty, error) {

	d.logger.DebugCtx(ctx, "set a new loadb alancer backend", slog.Any("backend", in))
	addr, err := netip.ParseAddr(in.Address)
	if err != nil {
		d.logger.ErrorCtx(ctx, "failed to parse ip", err, slog.String("ip", in.Address))
		return nil, err
	}

	backend := &loadbalancer.Backend{
		Name:        in.Name,
		Address:     addr,
		HealthCheck: in.Healthcheck,
	}

	if err := d.lb.Set(backend); err != nil {
		d.logger.ErrorCtx(ctx, "failed to set a new backend", err, slog.Any("backend", backend))
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (d *Daemon) LoadBalancerGet(ctx context.Context, in *rpc.LoadBalancerGetRequest) (*rpc.LoadBalancerGetResponse, error) {

	backends, err := d.lb.Get()
	if err != nil {
		return nil, err
	}

	protoBackends := make([]*rpc.LoadBalancerBackend, 0, len(backends))

	for _, b := range backends {
		d.logger.DebugCtx(ctx, "list backends", slog.Any("backend", b))
		protoBackends = append(protoBackends, &rpc.LoadBalancerBackend{
			Id:          int32(b.Id),
			Name:        b.Name,
			DevName:     b.Iface.Attrs().Name,
			IpAddr:      b.Address.String(),
			MacAddr:     b.MacAddress.String(),
			Healthcheck: b.HealthCheck,
			Status:      int32(b.Status),
		})
	}

	return &rpc.LoadBalancerGetResponse{
		Backends: protoBackends,
	}, nil
}

func (d *Daemon) LoadBalancerDelete(ctx context.Context, in *rpc.LoadBalancerDeleteRequest) (*emptypb.Empty, error) {

	if err := d.lb.Delete(uint32(in.Id)); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (d *Daemon) LoadBalancerDrain(ctx context.Context, in *rpc.LoadBalancerDrainRequest) (*emptypb.Empty, error) {

	if err := d.lb.Drain(uint32(in.Id)); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (d *Daemon) LoadBalancerConntrackGet(ctx context.Context, in *rpc.LoadBalancerConntrackGetRequest) (*rpc.LoadBalancerConntrackGetResponse, error) {

	entries, err := d.lb.GetConntrackEntries()
	if err != nil {
		return nil, err
	}

	protoEntries := make([]*rpc.ConntrackEntry, 0, len(entries))

	for _, e := range entries {
		protoEntries = append(protoEntries, &rpc.ConntrackEntry{
			SrcAddr:   e.SrcAddr.String(),
			DstAddr:   e.DstAddr.String(),
			SrcPort:   int32(e.SrcPort),
			DstPort:   int32(e.DstPort),
			Protocol:  int32(e.Protocol),
			Status:    int32(e.State),
			Timestamp: timestamppb.New(e.Timestamp),
			BackendId: int32(e.BackendId),
			Counter:   e.Counter,
		})
	}

	return &rpc.LoadBalancerConntrackGetResponse{
		Entries: protoEntries,
	}, nil
}
