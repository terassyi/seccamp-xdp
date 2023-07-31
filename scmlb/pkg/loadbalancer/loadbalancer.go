package loadbalancer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/logger"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/protocols"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/slog"
)

type LbBackendManager struct {
	mu                      *sync.Mutex
	logger                  *slog.Logger
	upstramInfo             Upstream
	vip                     netip.Addr
	entrypoint              *ebpf.Program
	backends                map[uint32]*Backend
	conntrack               map[conntrackKey]*ConntrackEntry
	interval                time.Duration
	gcEnabled               bool
	gcTime                  time.Duration
	nextId                  uint32
	registeredBackendLength uint32
	redirectMap             *ebpf.Map
	backendInfoMap          *ebpf.Map
	backendIfindexMap       *ebpf.Map
	upstreamMap             *ebpf.Map
	conntrackMap            *ebpf.Map
	rrTableMap              *ebpf.Map
}

func New(vip netip.Addr, upstreamIface string, entry *ebpf.Program, redirectMap, backendInfoMap, backendIfindexMap, upstreamMap *ebpf.Map, conntrack, rrTableMap *ebpf.Map, gcEnabled bool, gcTime time.Duration) (*LbBackendManager, error) {
	out, err := logger.Output(constants.LogOutput)
	if err != nil {
		return nil, err
	}

	logger := logger.SetUpLogger(constants.LogFormat, out, logger.ValidateLevel(constants.LogLevel))

	upstreamLink, err := netlink.LinkByName(upstreamIface)
	if err != nil {
		return nil, err
	}

	info := Upstream{
		IpAddr:  vip,
		Index:   uint32(upstreamLink.Attrs().Index),
		MacAddr: upstreamLink.Attrs().HardwareAddr,
	}

	logger.Debug("setup loadbalcner upstream information", slog.String("vip", info.IpAddr.String()), slog.String("iface", upstreamLink.Attrs().Name), slog.String("mac addr", info.MacAddr.String()))

	return &LbBackendManager{
		logger:                  logger,
		mu:                      &sync.Mutex{},
		vip:                     vip,
		upstramInfo:             info,
		entrypoint:              entry,
		backends:                make(map[uint32]*Backend),
		conntrack:               make(map[conntrackKey]*ConntrackEntry),
		interval:                time.Second,
		gcEnabled:               gcEnabled,
		gcTime:                  gcTime,
		nextId:                  1,
		registeredBackendLength: 0,
		redirectMap:             redirectMap,
		backendInfoMap:          backendInfoMap,
		backendIfindexMap:       backendIfindexMap,
		upstreamMap:             upstreamMap,
		conntrackMap:            conntrack,
		rrTableMap:              rrTableMap,
	}, nil
}

type Backend struct {
	Id          uint32
	Name        string
	Address     netip.Addr
	MacAddress  net.HardwareAddr
	Iface       netlink.Link
	Status      BackendStatus
	HealthCheck string
	finalizer   func() error
}

type BackendStatus uint32

const (
	BackendStatusAvailable  BackendStatus = BackendStatus(0)
	BackenStatusUnavailable BackendStatus = BackendStatus(1)
)

func (b BackendStatus) String() string {
	switch b {
	case BackendStatusAvailable:
		return "Available"
	case BackenStatusUnavailable:
		return "Unavailable"
	default:
		return "Unknown"
	}
}

type backendInfo struct {
	Id         uint32
	Index      uint32
	Satus      uint32
	SrcMacAddr [6]uint8
	DstMacAddr [6]uint8
	DstIpAddr  uint32
}

type Upstream struct {
	IpAddr  netip.Addr
	Index   uint32
	MacAddr net.HardwareAddr
}

type upstreamInfo struct {
	IpAddr  uint32
	IfIndex uint16
	MacAddr [6]uint8
}

func (l *LbBackendManager) Run(ctx context.Context) error {

	// upstream の情報を bpf マップに格納して XDP プログラム側から読み取れるようにします。
	info := upstreamInfo{
		IpAddr:  protocols.IpAddrToU32Le(l.upstramInfo.IpAddr),
		IfIndex: uint16(l.upstramInfo.Index),
		MacAddr: [6]uint8(l.upstramInfo.MacAddr),
	}

	l.logger.DebugCtx(ctx, "insert upstream information to bpf map", slog.Any("upstream", info))
	if err := l.upstreamMap.Update(uint32(0), info, ebpf.UpdateAny); err != nil {
		return err
	}

	l.logger.DebugCtx(ctx, "insert upstream ifindex to redirect map", slog.Int("ifindex", int(info.IfIndex)))
	if err := l.redirectMap.Update(l.upstramInfo.Index, l.upstramInfo.Index, ebpf.UpdateAny); err != nil {
		return err
	}

	l.logger.InfoCtx(ctx, "starting conntrack loop")

	ticker := time.NewTicker(l.interval)
	for {
		select {
		case <-ticker.C:
			if err := l.sync(); err != nil {
				l.logger.ErrorCtx(ctx, "failed to sync conntrack", err)
			}
			if err := l.gc(); err != nil {
				l.logger.ErrorCtx(ctx, "failed to gc conntrack", err)
			}
		case <-ctx.Done():
			l.logger.InfoCtx(ctx, "stopping conntrack loop")
			return nil
		}
	}
}

func (l *LbBackendManager) sync() error {

	iter := l.conntrackMap.Iterate()

	var (
		key   conntrackKey
		value conntrackInfo
		errs  []error = []error{}
	)

	gcEtnries := make([]conntrackKey, 0)

	for iter.Next(&key, &value) {
		l.logger.Debug("iterate conntrack entries", slog.Any("key", key), slog.Any("value", value))

		srcAddr, err := protocols.IpAddrFromLe(key.SrcAddr)
		if err != nil {
			errs = append(errs, err)
		}
		dstAddr, err := protocols.IpAddrFromLe(key.DstAddr)
		if err != nil {
			errs = append(errs, err)
		}

		entry, ok := l.conntrack[key]
		if !ok {
			entry := &ConntrackEntry{
				SrcAddr:   srcAddr,
				DstAddr:   dstAddr,
				SrcPort:   uint32(protocols.Ntohs(key.SrcPort)),
				DstPort:   uint32(protocols.Ntohs(key.DstPort)),
				Protocol:  protocols.TransportProtocol(key.Protocol),
				State:     ConnectionState(value.Status),
				BackendId: value.Id,
				Counter:   value.Counter,
				Timestamp: time.Now(),
			}
			l.conntrack[key] = entry
			continue
		}
		entry.State = ConnectionState(value.Status)
		if entry.Counter < value.Counter {
			entry.Timestamp = time.Now()
		}
		entry.Counter = value.Counter

		// GC 対象のエントリを一時的に保存します。
		// GC の対象となるのは TCP で 状態が CLosed なものと、UDP で最新のパケットがやり取りされてから gcTime 以上の時間が経っているエントリーです。
		if entry.State == ConnectionStateClosed {
			newKey := conntrackKey{
				SrcAddr:  key.SrcAddr,
				DstAddr:  key.DstAddr,
				SrcPort:  key.SrcPort,
				DstPort:  key.DstPort,
				Protocol: key.Protocol,
			}
			gcEtnries = append(gcEtnries, newKey)
		} else if entry.Protocol == protocols.TransportProtocolUdp && time.Since(entry.Timestamp) > l.gcTime {
			newKey := conntrackKey{
				SrcAddr:  key.SrcAddr,
				DstAddr:  key.DstAddr,
				SrcPort:  key.SrcPort,
				DstPort:  key.DstPort,
				Protocol: key.Protocol,
			}
			gcEtnries = append(gcEtnries, newKey)
		}
	}

	// GC の対象となったエントリーを削除して bpf マップからも削除します。
	for _, gcEntry := range gcEtnries {
		err := l.conntrackMap.Delete(gcEntry)
		if err != nil {
			errs = append(errs, err)
		} else {
			delete(l.conntrack, gcEntry)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (l *LbBackendManager) gc() error {
	// GC 有効化フラグが立っていない場合はなにもしません。
	if !l.gcEnabled {
		return nil
	}
	return nil
}

// ロードバランサーのバックエンドを追加します。
func (l *LbBackendManager) Set(backend *Backend) error {

	if err := learnMacAddr(backend.Address); err != nil {
		return err
	}

	entry, err := getBackendDeviceInfo(backend.Address)
	if err != nil {
		return err
	}

	iface, err := netlink.LinkByName(entry.device)
	if err != nil {
		return err
	}

	backend.Id = l.nextId
	l.nextId += 1

	backend.MacAddress = entry.macAddr
	backend.Iface = iface
	backend.Status = BackendStatusAvailable

	// バックエンドの情報を各種マップに登録します。
	ifindex := uint32(backend.Iface.Attrs().Index)
	info := backendInfo{
		Id:         backend.Id,
		Index:      ifindex,
		Satus:      uint32(0),
		DstIpAddr:  protocols.IpAddrToU32Le(backend.Address),
		SrcMacAddr: [6]uint8(backend.Iface.Attrs().HardwareAddr),
		DstMacAddr: [6]uint8(backend.MacAddress),
	}

	l.logger.Debug("insert backend information to backend_info map", slog.Int("id", int(info.Id)), slog.Any("info", info))
	if err := l.backendInfoMap.Update(info.Id, info, ebpf.UpdateAny); err != nil {
		return err
	}

	l.logger.Debug("infex backend ifindex and id to backend_ifindex map", slog.Int("ifindex", int(ifindex)), slog.Int("id", int(info.Id)))
	if err := l.backendIfindexMap.Update(ifindex, info.Id, ebpf.UpdateAny); err != nil {
		return err
	}

	l.logger.Debug("insert backend interface index to backend redirect device map", slog.Any("info", info))
	if err := l.redirectMap.Update(ifindex, ifindex, ebpf.UpdateAny); err != nil {
		return err
	}

	l.logger.Debug("insert new backend id to rr_table.", slog.Int("index", int(l.registeredBackendLength)), slog.Int("backend id", int(backend.Id)))
	if err := l.rrTableMap.Update(l.registeredBackendLength, backend.Id, ebpf.UpdateAny); err != nil {
		return err
	}

	// 登録して RrTable の格納数が増えたらインクリメントします。
	l.registeredBackendLength += 1

	// 指定されたデバイスに XDP プログラムをアタッチします
	l.logger.Info("attach xdp entrypoint program", slog.String("device", backend.Iface.Attrs().Name), slog.Any("backend", backend))
	ll, err := link.AttachXDP(link.XDPOptions{
		Program: l.entrypoint,
		// アタッチしたいインターフェースのインデックスを指定します
		Interface: iface.Attrs().Index,
		// ここでは Generic XDP を利用するので XDPGenericMode を指定しています
		// Native XDP で動かしたい場合は XDPDriverMode を指定します。
		Flags: link.XDPGenericMode,
	})
	if err != nil {
		return err
	}

	finalizer := func() error {
		return ll.Close()
	}

	backend.finalizer = finalizer

	l.mu.Lock()
	defer l.mu.Unlock()

	l.logger.Debug("register a backend", slog.Any("backend", backend))
	l.backends[backend.Id] = backend

	return nil
}

// ロードバランサーに紐付けられているバックエンドのリストを取得します。
func (l *LbBackendManager) Get() ([]Backend, error) {

	l.logger.Info("get backend list")

	l.mu.Lock()
	defer l.mu.Unlock()

	backends := make([]Backend, 0, len(l.backends))

	for _, v := range l.backends {
		backends = append(backends, Backend{
			Id:          v.Id,
			Name:        v.Name,
			Address:     v.Address,
			MacAddress:  v.MacAddress,
			Iface:       v.Iface,
			HealthCheck: v.HealthCheck,
			Status:      v.Status,
		})
	}
	return backends, nil
}

// ロードバランサーのバックエンドを削除します。
func (l *LbBackendManager) Delete(id uint32) error {

	backend, ok := l.backends[id]
	if !ok {
		return nil
	}

	var info backendInfo

	if err := l.backendInfoMap.Lookup(id, &info); err != nil {
		l.logger.Error("failed to lookup backend", err, slog.Int("id", int(id)))
		return err
	}

	if info.Satus != uint32(BackenStatusUnavailable) {
		err := fmt.Errorf("backens status is not unavailable")
		l.logger.Error("drain before deleting backend", err, slog.Int("id", int(id)))
		return err
	}

	l.logger.Info("delete a backend", slog.Int("id", int(id)))

	// アタッチしている XDP プログラムをデタッチします。
	l.logger.Info("detach XDP program from backend", slog.Any("backend", backend))

	if err := backend.finalizer(); err != nil {
		l.logger.Error("failed to detach XDP program", err, slog.Any("backend", backend))
		return err
	}

	// 各種マップに格納している値を削除します。
	l.logger.Debug("delete from backend_info map", slog.Int("id", int(backend.Id)))
	if err := l.backendInfoMap.Delete(backend.Id); err != nil {
		return err
	}

	l.logger.Debug("delete from backend_ifindex map", slog.Int("ifindex", backend.Iface.Attrs().Index))
	if err := l.backendIfindexMap.Delete(uint32(backend.Iface.Attrs().Index)); err != nil {
		return err
	}

	l.logger.Debug("delete from backend redirect dev map", slog.Int("ifindex", backend.Iface.Attrs().Index))
	if err := l.redirectMap.Delete(uint32(backend.Iface.Attrs().Index)); err != nil {
		return err
	}

	delete(l.backends, id)

	return nil
}

func (l *LbBackendManager) DeleteAll() error {
	l.logger.Info("delete all backends")

	var errs []error

	for i, _ := range l.backends {
		err := l.Delete(i)
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// ロードバランサーのバックエンドを drain します。
// バックエンド削除の前準備のための処理です。
// 既存のコネクションを処理し続けたまま、新規のコネクションを受け付けないようにします。
func (l *LbBackendManager) Drain(id uint32) error {

	l.mu.Lock()
	defer l.mu.Unlock()

	backend, ok := l.backends[id]
	if !ok {
		l.logger.Warn("backend is not found", slog.Int("id", int(id)))
		return fmt.Errorf("backend is not found. id is %d", id)
	}

	// バックエンドステータスを Unavailable にセットします。
	backend.Status = BackenStatusUnavailable

	// bpf マップ上のステータスも Unavailable にします。
	var info backendInfo
	if err := l.backendInfoMap.Lookup(id, &info); err != nil {
		l.logger.Error("failed to lookup backend", err, slog.Int("id", int(id)))
		return err
	}

	info.Satus = uint32(BackenStatusUnavailable)

	if err := l.backendInfoMap.Update(id, info, ebpf.UpdateAny); err != nil {
		l.logger.Error("failed to update backend", err, slog.Int("id", int(id)), slog.Any("info", info))
		return err
	}

	if err := l.ajustRrTable(id); err != nil {
		l.logger.Error("failed to ajust round robin table map", err, slog.Int("id", int(id)))
		return err
	}

	return nil
}

func (l *LbBackendManager) ajustRrTable(id uint32) error {

	l.logger.Debug("ajust rr_table")
	// ラウンドロビンのテーブルを再調整する必要があります。

	backends := make([]backendInfo, 0, len(l.backends))

	for _, v := range l.backends {
		backends = append(backends, backendInfo{
			Id:    v.Id,
			Index: uint32(v.Iface.Attrs().Index),
			Satus: 0,
		})
	}
	sort.Slice(backends, func(i, j int) bool {
		return backends[i].Id < backends[j].Id
	})

	// 削除対象のバックエンド id が何番目にあるかを特定します。
	index := -1
	for i, b := range backends {
		if b.Id == id {
			index = i
			break
		}
	}
	if index == -1 {
		// バックエンドのリストに対象が含まれていないときはエラーを返します。
		return fmt.Errorf("backend is not found: %d", id)
	}
	// backends から対象のインデックスの要素を削除します
	backends = append(backends[:index], backends[index+1:]...)

	// rr_table の要素を再構成します
	for i := index; i < int(l.registeredBackendLength-1); i++ {
		l.logger.Debug("update rr_table", slog.Int("index", i), slog.Int("ifindex", int(backends[i].Index)))
		if err := l.rrTableMap.Update(uint32(i), backends[i].Id, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	// 最後の要素は 0 で更新します(要素が 1 つ削除されて末尾のインデックスは空になるはずなので)
	l.logger.Debug("refresh last index of rr_table", slog.Int("index", int(l.registeredBackendLength)-1))
	if err := l.rrTableMap.Update(l.registeredBackendLength-1, uint32(0), ebpf.UpdateAny); err != nil {
		return err
	}

	// 最後に登録しているバックエンドの数をデクリメントします。
	l.registeredBackendLength -= 1
	return nil
}

func (l *LbBackendManager) GetConntrackEntries() ([]ConntrackEntry, error) {

	l.mu.Lock()
	defer l.mu.Unlock()
	entries := make([]ConntrackEntry, 0, len(l.conntrack))

	for _, e := range l.conntrack {
		entries = append(entries, *e)
	}

	return entries, nil
}

func getBackendDeviceInfo(addr netip.Addr) (arpEntry, error) {

	addrMap, err := inspectArpTable()
	if err != nil {
		return arpEntry{}, err
	}
	info, ok := addrMap[addr]
	if !ok {
		return arpEntry{}, fmt.Errorf("failed to get device information for %s", addr.String())
	}

	return info, nil
}

const (
	arpTablePath string = "/proc/net/arp"
)

type arpEntry struct {
	ipAddr  netip.Addr
	macAddr net.HardwareAddr
	device  string
}

func inspectArpTable() (map[netip.Addr]arpEntry, error) {

	file, err := os.Open(arpTablePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// 以下のように /proc/net/arp ファイルの結果をパースして MAC アドレスとデバイス名を取得します。
	// $ cat /prpc/net/arp
	// IP address       HW type     Flags       HW address            Mask     Device
	// 10.0.0.2         0x1         0x2         6a:ad:44:35:5d:78     *        h0

	addrMap := make(map[netip.Addr]arpEntry)

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 || line == "" {
			// この行は ARP Table のヘッダ部分なので読み飛ばします。
			continue
		}
		d := strings.Split(strings.Join(strings.Fields(line), " "), " ")
		if len(d) < 6 {
			return nil, fmt.Errorf("failed to parse arp table file")
		}
		addr, err := netip.ParseAddr(d[0])
		if err != nil {
			return nil, err
		}
		maddr, err := net.ParseMAC(d[3])
		if err != nil {
			return nil, err
		}

		addrMap[addr] = arpEntry{
			ipAddr:  addr,
			macAddr: maddr,
			device:  d[5],
		}
	}

	return addrMap, nil
}

// ping コマンドを実行して Linux の arp table にバックエンドの MAC アドレスとパケットを送出すべきデバイスを登録します。
// 疎通確認も含めています。
func learnMacAddr(addr netip.Addr) error {
	cmd := exec.Command("ping", "-w", "1", "-c", "1", addr.String())
	return cmd.Run()
}
