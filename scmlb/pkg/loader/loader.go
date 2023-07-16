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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang XdpProg ../../bpf/xdp.c -- -I../../bpf/include

// bpf/xdp.c で定義された関数とマップのシンボルを定数として定義しています(使い回しがきくように)
const (
	PROG_NAME_ENTRYPOINY = "entrypoint"
	PROG_NAME_COUNT      = "count"

	MAP_NAME_CALLS_MAP = "calls_map"
	MAP_NAME_COUNTER   = "counter"
)

// tail call のための calls_map にデータを反映させるための map を定義しています。
var tailCalledPrograms = map[uint32]string{
	0: PROG_NAME_COUNT,
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

	logger.Info("load XDP programs")
	objects := XdpProgObjects{}
	// LoadXdpProgObjects() は bpf2go で自動生成された関数で、これを実行することで eBPF プログラムをカーネルにロードすることができます
	if err := LoadXdpProgObjects(&objects, nil); err != nil {
		return nil, err
	}

	programs := make(map[string]*ebpf.Program)
	maps := make(map[string]*ebpf.Map)

	programs[PROG_NAME_ENTRYPOINY] = objects.Entrypoint
	programs[PROG_NAME_COUNT] = objects.Count

	maps[MAP_NAME_CALLS_MAP] = objects.CallsMap
	maps[MAP_NAME_COUNTER] = objects.Counter

	return &Loader{
		logger:   logger,
		Programs: programs,
		Maps:     maps,
		links:    make(map[string]link.Link),
	}, nil
}

// この関数はカーネルにロードした XDP プログラムを NIC にアタッチしてパケット処理を開始させる関数です。
// XDP プログラムはロードする丈ではなくターゲットとなる NIC(インターフェース) にアタッチする必要があります
func (l *Loader) Attach(upstream string) error {
	// アタッチしたい NIC の名前からその NIC に関する情報を取得します
	iface, err := netlink.LinkByName(upstream)
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

	l.links[upstream] = ll

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
	}
	return nil
}

func (l *Loader) registerTailCall(index uint32, programName string) error {
	callsMap, ok := l.Maps[MAP_NAME_CALLS_MAP]
	if !ok {
		return fmt.Errorf("calls_map is not found")
	}

	callee, ok := l.Programs[PROG_NAME_COUNT]
	if !ok {
		return fmt.Errorf("%s is not found", MAP_NAME_COUNTER)
	}

	// calls_map に登録したいインデックス番号とそのプログラムへのファイルディスクリプタの値をマップに登録することで tail call 呼び出しが可能になります。
	return callsMap.Update(index, uint32(callee.FD()), ebpf.UpdateAny)
}
