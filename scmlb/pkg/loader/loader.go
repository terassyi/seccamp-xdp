package loader

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/slog"
)

// $ go generate を実行すると下に記述したコマンドが実行されます。
// ここでは bpf2go というプログラムを go コマンドを経由して実行しています。
// bpf2go は eBPF プログラムをコンパイルして ELF ファイルを生成したあと、go 言語から扱えるように go 言語のコードを自動生成してくれます。
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang XdpProg ../../bpf/xdp.c -g -- -I../../bpf/include

// bpf/xdp.c で定義された関数とマップのシンボルを定数として定義しています(使い回しがきくように)
const (
	PROG_NAME_ENTRYPOINY    = "entrypoint"
	PROG_NAME_COUNT         = "count"
	PROG_NAME_FIREWALL      = "firewall"
	PROG_NAME_DOS_PROTECTOR = "dos_protector"
	PROG_NAME_LB_INGRESS    = "lb_ingress"
	PROG_NAME_LB_EGRESS     = "lb_egress"

	MAP_NAME_CALLS_MAP        = "calls_map"
	MAP_NAME_COUNTER          = "counter"
	MAP_NAME_RULES            = "rules"
	MAP_NAME_DROP_COUNTER     = "drop_counter"
	MAP_NAME_ADV_RULE_MATCHER = "adv_rulematcher"
	MAP_NAME_ADV_RULES        = "adv_rules"
	MAP_NAME_DOSP_COUNTER     = "dosp_counter"
	MAP_NAME_REDIRECT_DEV_MAP = "redirect_dev_map"
	MAP_NAME_BACKEND_IFINDEX  = "backend_ifindex"
	MAP_NAME_BACKEND_INFO     = "backend_info"
	MAP_NAME_UPSTREAM_INFO    = "upstream_info"
	MAP_NAME_CONNTRACK        = "conntrack"
	MAP_NAME_RR_TABLE         = "rr_table"

	PinBasePath = "/sys/fs/bpf/scmlb"
)

// tail call のための calls_map にデータを反映させるための map を定義しています。
var tailCalledPrograms = map[uint32]string{
	0: PROG_NAME_COUNT,
	1: PROG_NAME_FIREWALL,
	2: PROG_NAME_DOS_PROTECTOR,
	3: PROG_NAME_LB_INGRESS,
	4: PROG_NAME_LB_EGRESS,
}

// bpf/xdp.c から生成した関数やマップの情報を保持する構造体
type Loader struct {
	logger   slog.Logger
	Programs map[string]*ebpf.Program
	Maps     map[string]*ebpf.Map
	links    map[string]link.Link
}

// この関数は bpf/xdp.c で定義した eBPF プログラムをカーネルにロードします
func Load(logger slog.Logger) (*Loader, error) {

	// if err := os.Mkdir(PinBasePath, os.ModePerm); err != nil {
	// return nil, err
	// }

	logger.Info("load XDP programs")
	objects := XdpProgObjects{}
	// LoadXdpProgObjects() は bpf2go で自動生成された関数で、これを実行することで eBPF プログラムをカーネルにロードすることができます
	if err := LoadXdpProgObjects(&objects, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  ebpf.DefaultVerifierLogSize * 256,
		},
		// Maps: ebpf.MapOptions{
		// PinPath: PinBasePath,
		// },
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("Verifier error: %+v\n", ve)
			return nil, err
		}
		return nil, err
	}

	programs := make(map[string]*ebpf.Program)
	maps := make(map[string]*ebpf.Map)

	programs[PROG_NAME_ENTRYPOINY] = objects.Entrypoint
	programs[PROG_NAME_COUNT] = objects.Count
	programs[PROG_NAME_FIREWALL] = objects.Firewall
	programs[PROG_NAME_DOS_PROTECTOR] = objects.DosProtector
	programs[PROG_NAME_LB_INGRESS] = objects.LbIngress
	programs[PROG_NAME_LB_EGRESS] = objects.LbEgress

	maps[MAP_NAME_CALLS_MAP] = objects.CallsMap
	maps[MAP_NAME_COUNTER] = objects.Counter
	maps[MAP_NAME_RULES] = objects.Rules
	maps[MAP_NAME_DROP_COUNTER] = objects.DropCounter
	maps[MAP_NAME_ADV_RULE_MATCHER] = objects.AdvRulematcher
	maps[MAP_NAME_ADV_RULES] = objects.AdvRules
	maps[MAP_NAME_DOSP_COUNTER] = objects.DospCounter
	maps[MAP_NAME_REDIRECT_DEV_MAP] = objects.RedirectDevMap
	maps[MAP_NAME_BACKEND_INFO] = objects.BackendInfo
	maps[MAP_NAME_BACKEND_IFINDEX] = objects.BackendIfindex
	maps[MAP_NAME_UPSTREAM_INFO] = objects.UpstreamInfo
	maps[MAP_NAME_CONNTRACK] = objects.Conntrack
	maps[MAP_NAME_RR_TABLE] = objects.RrTable

	return &Loader{
		logger:   logger,
		Programs: programs,
		Maps:     maps,
		links:    make(map[string]link.Link),
	}, nil
}

// この関数はカーネルにロードした XDP プログラムを NIC にアタッチしてパケット処理を開始させる関数です。
// XDP プログラムはロードする丈ではなくターゲットとなる NIC(インターフェース) にアタッチする必要があります
func (l *Loader) Attach(device string) error {
	// アタッチしたい NIC の名前からその NIC に関する情報を取得します
	iface, err := netlink.LinkByName(device)
	if err != nil {
		return err
	}

	l.logger.Info("attach a XDP entrypoint program to the upstream interface")

	// 実際にプログラムをアタッチします
	ll, err := link.AttachXDP(link.XDPOptions{
		Program: l.Programs[PROG_NAME_ENTRYPOINY],
		// アタッチしたいインターフェースのインデックスを指定します
		Interface: iface.Attrs().Index, //
		// ここでは Generic XDP を利用するので XDPGenericMode を指定しています
		// Native XDP で動かしたい場合は XDPDriverMode を指定します。
		Flags: link.XDPGenericMode,
	})
	if err != nil {
		return err
	}

	l.links[device] = ll

	return nil
}

// この関数は プログラム終了時にカーネルにロード、 NIC にアタッチしたXDP プログラムや eBPF マップの後片付けを行う関数です。
func (l *Loader) Finalize() error {
	errs := []error{}
	for _, p := range l.Programs {
		err := p.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	for _, m := range l.Maps {
		err := m.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	for _, ll := range l.links {
		err := ll.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// この関数は tail call で呼び出す関数を calls_map に登録する関数です。
func (l *Loader) RegisterTailCall() error {
	for k, v := range tailCalledPrograms {
		if err := l.registerTailCall(k, v); err != nil {
			l.logger.Error("failed to register tail called program", err, slog.Int("array_index", int(k)), slog.String("name", v), slog.Int("program_fd", l.Programs[v].FD()))
			return err
		}
		l.logger.Info("register tail called function", slog.String("name", v), slog.Int("index", int(k)))
	}
	return nil
}

func (l *Loader) registerTailCall(index uint32, programName string) error {
	callsMap, ok := l.Maps[MAP_NAME_CALLS_MAP]
	if !ok {
		return fmt.Errorf("calls_map is not found")
	}

	callee, ok := l.Programs[programName]
	if !ok {
		return fmt.Errorf("%s is not found", programName)
	}

	// calls_map に登録したいインデックス番号とそのプログラムへのファイルディスクリプタの値をマップに登録することで tail call 呼び出しが可能になります。
	return callsMap.Update(index, uint32(callee.FD()), ebpf.UpdateAny)
}
