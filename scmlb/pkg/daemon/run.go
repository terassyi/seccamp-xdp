package daemon

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/counter"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/dosprotector"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/firewall"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/loadbalancer"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/loader"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/logger"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/rpc"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Daemon struct {
	logger    *slog.Logger
	apiAddr   string
	apiPort   int32
	apiServer *grpc.Server
	upstream  string
	rpc.UnimplementedScmLbApiServer

	counter      *counter.Counter
	fw           *firewall.FwManager
	dosProtector *dosprotector.DoSProtector
	lb           *loadbalancer.LbBackendManager
}

func New(apiAddr string, apiPort int32, upstreamInterface string) (*Daemon, error) {
	out, err := logger.Output(constants.LogOutput)
	if err != nil {
		return nil, err
	}
	logger := logger.SetUpLogger(constants.LogFormat, out, logger.ValidateLevel(constants.LogLevel))

	daemon := &Daemon{
		logger:    logger,
		apiPort:   apiPort,
		apiServer: grpc.NewServer(),
		upstream:  upstreamInterface,
	}
	return daemon, nil
}

func (d *Daemon) Run(vip netip.Addr, gc bool, gcTime time.Duration) error {

	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	d.logger.InfoCtx(ctx, "start scmlbd")

	// Ctrl-C でプログラムを終了できるようにしています
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh,
		syscall.SIGINT,
		syscall.SIGTERM,
	)

	// CLI クライアント(scmlb コマンド) と通信するための gRPC サーバーを起動しています
	rpc.RegisterScmLbApiServer(d.apiServer, d)
	reflection.Register(d.apiServer)

	listerner, err := net.Listen("tcp", fmt.Sprintf(":%d", d.apiPort))
	if err != nil {
		return err
	}

	// goroutine(軽量スレッド) として gRPC サーバーの待受を開始しています
	go func() {
		if err := d.apiServer.Serve(listerner); err != nil {
			panic(fmt.Sprintf("API server panic: %s", err))
		}
	}()

	d.logger.InfoCtx(ctx, "load XDP components")

	// bpf/xdp.c に定義された XDP プログラムをロードしています
	loader, err := loader.Load(*d.logger)
	if err != nil {
		return err
	}

	// エントリーポイントから tail call で呼び出される関数を calls_map(BPF_MAP_TYPE_PROG_ARRAY) に登録しています
	// $ bpftool prog list / $ bpftool map show でロードされていることを確認できます(プログラム動作時のみ)
	if err := loader.RegisterTailCall(); err != nil {
		return err
	}

	// 各種機能をセットアップします。
	d.logger.InfoCtx(ctx, "setup packet counter")
	if err := d.setupCounter(d.upstream, loader); err != nil {
		return err
	}
	d.logger.InfoCtx(ctx, "setup firewall")
	if err := d.setupFirewall(loader); err != nil {
		return err
	}
	d.logger.InfoCtx(ctx, "setup DoS protector")
	if err := d.setupDoSProtector(ctx, loader, d.fw); err != nil {
		return err
	}

	d.logger.InfoCtx(ctx, "setup Load balancer")
	if err := d.setupLoadBalancer(ctx, loader, vip, gc, gcTime); err != nil {
		return err
	}

	// ロードしたプログラムを NIC にアタッチします
	if err := loader.Attach(d.upstream); err != nil {
		return err
	}

	// defer に登録された関数は登録元の関数(この場合は Run() )から抜けるときに実行されます。
	// ここではロードした XDP プログラムと eBPF マップを削除して、アタッチしている NIC からもプログラムを外しています。
	defer func() {

		d.logger.InfoCtx(ctx, "stopping scmlbd")
		// ロードバランサーのバックエンドにアタッチしている XDP プログラムもでタッチします。
		if err := d.lb.DeleteAll(); err != nil {
			d.logger.ErrorCtx(ctx, "failed to finalize XDP from backends", err)
		}

		if err := loader.Finalize(); err != nil {
			d.logger.ErrorCtx(ctx, "failed to finalize XDP", err)
		}
		d.logger.InfoCtx(ctx, "finished stopping lb")
	}()

	// Ctrl-C を待ち受けています
	// シグナルを受け取ると即時リターンしますが、その前に defer で登録した関数が実行されます
	<-signalCh
	return nil
}

// ingress_counter 機能のセットアップを行います
func (d *Daemon) setupCounter(name string, l *loader.Loader) error {
	program, ok := l.Programs[loader.PROG_NAME_COUNT]
	if !ok {
		return fmt.Errorf("failed to find ingress_count program")
	}
	m, ok := l.Maps[loader.MAP_NAME_COUNTER]
	if !ok {
		return fmt.Errorf("failed to find ingress_counter map")
	}
	c, err := counter.New(name, program, m)
	if err != nil {
		return err
	}
	d.counter = c
	return nil
}

func (d *Daemon) setupFirewall(l *loader.Loader) error {
	p, ok := l.Programs[loader.PROG_NAME_FIREWALL]
	if !ok {
		return fmt.Errorf("failed to find firewall program")
	}
	rm, ok := l.Maps[loader.MAP_NAME_RULES]
	if !ok {
		return fmt.Errorf("failed to find firewall map")
	}
	dm, ok := l.Maps[loader.MAP_NAME_DROP_COUNTER]
	if !ok {
		return fmt.Errorf("failed to find drop_counter")
	}
	arm, ok := l.Maps[loader.MAP_NAME_ADV_RULE_MATCHER]
	if !ok {
		return fmt.Errorf("failed to find adv_rulematcher")
	}
	ar, ok := l.Maps[loader.MAP_NAME_ADV_RULES]
	if !ok {
		return fmt.Errorf("failed to find adv_rules")
	}

	f := firewall.NewManager(d.logger, p, rm, dm, arm, ar)
	d.fw = f

	return nil
}

func (d *Daemon) setupDoSProtector(ctx context.Context, l *loader.Loader, fwManager *firewall.FwManager) error {

	counter, ok := l.Maps[loader.MAP_NAME_DOSP_COUNTER]
	if !ok {
		return fmt.Errorf("failed to find policies map")
	}

	p, err := dosprotector.New(fwManager, counter)
	if err != nil {
		return err
	}

	d.dosProtector = p

	d.logger.InfoCtx(ctx, "start DoS protector loop")
	go func() {
		if err := d.dosProtector.Run(ctx); err != nil {
			panic(err)
		}
	}()

	return nil
}

func (d *Daemon) setupLoadBalancer(ctx context.Context, l *loader.Loader, vip netip.Addr, gc bool, gcTime time.Duration) error {
	entry, ok := l.Programs[loader.PROG_NAME_ENTRYPOINY]
	if !ok {
		return fmt.Errorf("failed to find entrypoint program")
	}

	redirectMap, ok := l.Maps[loader.MAP_NAME_REDIRECT_DEV_MAP]
	if !ok {
		return fmt.Errorf("failed to find backend device map")
	}

	backendInfoMap, ok := l.Maps[loader.MAP_NAME_BACKEND_INFO]
	if !ok {
		return fmt.Errorf("failed to find backend info map")
	}
	backendIfindexMap, ok := l.Maps[loader.MAP_NAME_BACKEND_IFINDEX]
	if !ok {
		return fmt.Errorf("failed to find bakcend ifindex map")
	}
	upstreamMap, ok := l.Maps[loader.MAP_NAME_UPSTREAM_INFO]
	if !ok {
		return fmt.Errorf("failed to find upstream info")
	}
	conntrack, ok := l.Maps[loader.MAP_NAME_CONNTRACK]
	if !ok {
		return fmt.Errorf("failed to find conntrack map")
	}
	rrTableMap, ok := l.Maps[loader.MAP_NAME_RR_TABLE]
	if !ok {
		return fmt.Errorf("failed to find rr_table map")
	}

	lbm, err := loadbalancer.New(vip, d.upstream, entry, redirectMap, backendInfoMap, backendIfindexMap, upstreamMap, conntrack, rrTableMap, gc, gcTime)
	if err != nil {
		return err
	}

	d.lb = lbm

	d.logger.InfoCtx(ctx, "start Load balancer loop")
	go func() {
		if err := d.lb.Run(ctx); err != nil {
			panic(err)
		}
	}()
	return nil
}
