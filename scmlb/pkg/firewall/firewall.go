package firewall

import (
	"encoding/binary"
	"net/netip"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/protocols"
	"golang.org/x/exp/slog"
)

type FWRule struct {
	Id       uint32
	Prefix   netip.Prefix
	FromPort uint32
	ToPort   uint32
	Protocol protocols.TransportProtocol
	Count    uint64
}

// この構造体は bpf/include/scmlb.h の同名の構造体に対応しています。
type network struct {
	prefixLen uint32
	address   uint32
}

// この構造体は bpf/include/scmlb.h の同名の構造体に対応しています。
type fwRule struct {
	id       uint32
	fromPort uint16
	toPort   uint16
	protocol uint32
}

type FwManager struct {
	logger         *slog.Logger
	mu             *sync.Mutex
	rules          map[uint32]FWRule
	nextId         uint32
	p              *ebpf.Program
	ruleMap        *ebpf.Map
	dropCounter    *ebpf.Map
	advRuleMatcher *ebpf.Map
	advRuleMap     *ebpf.Map
}

func NewManager(logger *slog.Logger, p *ebpf.Program, ruleMap, dropCounter, advRuleMatcher, advRuleMap *ebpf.Map) *FwManager {
	return &FwManager{
		logger:         logger,
		mu:             &sync.Mutex{},
		rules:          make(map[uint32]FWRule),
		nextId:         1,
		ruleMap:        ruleMap,
		dropCounter:    dropCounter,
		advRuleMatcher: advRuleMatcher,
		advRuleMap:     advRuleMap,
	}
}

func (f *FwManager) Set(rule *FWRule) (uint32, error) {

	rule.Id = f.nextId
	f.nextId += 1

	f.mu.Lock()
	defer f.mu.Unlock()

	// ここで eBPF マップにルールを追加します

	nw, r := rule.splitKeyValue()
	if err := f.ruleMap.Update(nw, r, ebpf.UpdateAny); err != nil {
		f.logger.Error("failed to update rule map", err, slog.Int("id", int(r.id)), slog.String("network", rule.Prefix.String()))
		return 0, err
	}

	// port や protocol を考慮した fire wall のためのコード
	var ids [constants.ADVANCED_FIRE_WALL_MAX_SIZE_PER_NETWORK]uint16

	if err := f.advRuleMatcher.Lookup(nw, &ids); err != nil {
		f.logger.Error("failed to lookup rule matcher", err, slog.Any("rule", rule))
	}

	f.logger.Debug("ids", slog.Any("ids", ids))

	for i := 0; i < constants.ADVANCED_FIRE_WALL_MAX_SIZE_PER_NETWORK; i++ {
		if ids[i] == 0 {
			ids[i] = uint16(rule.Id)
			break
		}
	}

	f.logger.Debug("update rule matcher", slog.String("network", rule.Prefix.String()), slog.Any("ids", ids))
	if err := f.advRuleMatcher.Update(nw, &ids, ebpf.UpdateAny); err != nil {
		f.logger.Error("failed to update rule matcher", err, slog.Any("rule", rule), slog.Any("ids", ids))
		return 0, err
	}

	if err := f.advRuleMap.Update(rule.Id, r, ebpf.UpdateAny); err != nil {
		f.logger.Error("failed to update advanced rule map", err, slog.Int("id", int(r.id)), slog.String("network", rule.Prefix.String()))
		return 0, err
	}

	f.rules[rule.Id] = *rule

	return rule.Id, nil
}

func (f *FwManager) Get() ([]FWRule, error) {

	rules := make([]FWRule, 0, len(f.rules))

	f.mu.Lock()
	defer f.mu.Unlock()

	for _, v := range f.rules {
		// drop_counter ebpf Map から値を取り出します
		var dropped uint64
		f.logger.Debug("lookup drop counter", slog.Any("rule", v))
		if err := f.dropCounter.Lookup(v.Id, &dropped); err != nil {
			f.logger.Error("failed to lookup drop counter", err, slog.Int("id", int(v.Id)))
			v.Count = 0
		} else {
			v.Count = dropped
		}

		rules = append(rules, v)
	}

	return rules, nil
}

func (f *FwManager) Delete(id uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	rule, ok := f.rules[id]
	if !ok {
		return nil
	}

	nw, _ := rule.splitKeyValue()

	// ここで eBPF マップから指定された id のルールを削除します
	if err := f.ruleMap.Delete(nw.toUint64()); err != nil {
		return err
	}
	if err := f.dropCounter.Delete(id); err != nil {
		f.logger.Warn("failed to delete a drop counter entry", slog.Int("id", int(id)))
	}

	// port と protocol を考慮した fire wall のためのコード
	var ids [constants.ADVANCED_FIRE_WALL_MAX_SIZE_PER_NETWORK]uint16

	if err := f.advRuleMatcher.Lookup(nw, &ids); err != nil {
		f.logger.Error("failed to lookup rule matcher", err, slog.Any("rule", rule))
	}

	f.logger.Debug("ids", slog.Any("ids", ids))

	var newIds [constants.ADVANCED_FIRE_WALL_MAX_SIZE_PER_NETWORK]uint16
	index := 0

	for i := 0; i < constants.ADVANCED_FIRE_WALL_MAX_SIZE_PER_NETWORK; i++ {
		if ids[i] != uint16(id) && ids[i] != 0 {
			newIds[index] = ids[i]
			index += 1
		}
	}

	f.logger.Debug("update rule matcher", slog.String("network", rule.Prefix.String()), slog.Any("ids", ids))
	if err := f.advRuleMatcher.Update(nw, &ids, ebpf.UpdateAny); err != nil {
		f.logger.Error("failed to update rule matcher", err, slog.Any("rule", rule), slog.Any("ids", ids))
		return err
	}

	f.logger.Info("delete rule", slog.Int("id", int(id)), slog.Any("rule", rule))
	if err := f.advRuleMap.Delete(rule.Id); err != nil {
		f.logger.Error("failed to update advanced rule map", err, slog.Int("id", int(id)), slog.String("network", rule.Prefix.String()))
		return err
	}

	delete(f.rules, id)

	return nil
}

func (r *FWRule) splitKeyValue() (network, fwRule) {
	addr := r.Prefix.Addr().As4()
	// ここはリトルエンディアンで格納します
	addrN := binary.LittleEndian.Uint32(addr[:])
	nw := network{
		prefixLen: uint32(r.Prefix.Bits()),
		address:   addrN,
	}

	rule := fwRule{
		id:       r.Id,
		fromPort: uint16(r.FromPort),
		toPort:   uint16(r.ToPort),
		protocol: uint32(r.Protocol),
	}

	return nw, rule
}

func (n network) toUint64() uint64 {
	return (uint64(n.address) << 32) + uint64(n.prefixLen)
}
