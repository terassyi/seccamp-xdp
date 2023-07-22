package dosprotector

import (
	"context"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/constants"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/firewall"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/logger"
	"github.com/terassyi/seccamp-xdp/scmlb/pkg/protocols"
	"golang.org/x/exp/slog"
)

// DoS protector のマネージャーの構造体です。
// 適用されたポリシーのリストや fire wall を管理するマネージャーへのポインタを保持しています。
type DoSProtector struct {
	logger     *slog.Logger
	mu         *sync.Mutex
	counterMap *ebpf.Map
	counter    map[identifier]uint64
	policies   map[uint32]*Policy
	nextId     uint32
	fwManager  *firewall.FwManager
}

func New(fwManager *firewall.FwManager, counterMap *ebpf.Map) (*DoSProtector, error) {
	out, err := logger.Output(constants.LogOutput)
	if err != nil {
		return nil, err
	}

	logger := logger.SetUpLogger(constants.LogFormat, out, logger.ValidateLevel(constants.LogLevel))

	return &DoSProtector{
		logger:     logger,
		mu:         &sync.Mutex{},
		counterMap: counterMap,
		counter:    make(map[identifier]uint64),
		policies:   make(map[uint32]*Policy),
		nextId:     1,
		fwManager:  fwManager,
	}, nil
}

// 適用する DoS protection policy の実体です。
type Policy struct {
	mu *sync.Mutex
	Id uint32
	// icmp, tcp, udp プロトコルのいずれかを想定しています。
	Protocol protocols.TransportProtocol
	// tcp でのみ使用するので tcp flag のみを受け付けるようにしています。
	Type protocols.TcpFlag
	// 計測インターバル間で許容するパケット数です。これを超えると fire wall に送信元のアドレスをブロックするルールを追加します。
	Limit  uint64
	Status PolicyStatus
	// このポリシーが適用している fire wall ルールのリストです。
	FwRuleIds []uint32
}

type PolicyStatus uint

const (
	PolicyStatusNotTriggered PolicyStatus = 0
	PolicyStatusTriggered    PolicyStatus = 1
	PolicyStatusUnknown      PolicyStatus = 255
)

func (p PolicyStatus) String() string {
	switch p {
	case PolicyStatusNotTriggered:
		return "not triggered"
	case PolicyStatusTriggered:
		return "triggered"
	default:
		return "unknown"
	}
}

// dosp_protection_identifier bpf map に対応する構造体です。
// この構造体を通して bpf プログラムとやり取りします。
type identifier struct {
	Address  uint32
	Protocol uint8
	Type     uint8
}

// ポリシーをセットします
func (d *DoSProtector) Set(ctx context.Context, policy *Policy) (uint32, error) {

	// 足りないフィールドを埋めていきます
	policy.mu = &sync.Mutex{}
	policy.Id = d.nextId
	d.nextId += 1
	policy.Status = PolicyStatusNotTriggered
	policy.FwRuleIds = make([]uint32, 0)

	d.mu.Lock()
	defer d.mu.Unlock()

	d.policies[policy.Id] = policy

	return policy.Id, nil
}

// セットされているポリシーの一覧を取得します。
func (d *DoSProtector) Get() ([]Policy, error) {

	policies := make([]Policy, 0, len(d.policies))

	d.mu.Lock()
	defer d.mu.Unlock()

	for _, v := range d.policies {
		v.mu.Lock()

		policies = append(policies, Policy{
			Id:        v.Id,
			Protocol:  v.Protocol,
			Type:      v.Type,
			Limit:     v.Limit,
			Status:    v.Status,
			FwRuleIds: v.FwRuleIds,
		})

		v.mu.Unlock()
	}

	return policies, nil
}

// ポリシーを削除します。
func (d *DoSProtector) Delete(id uint32) error {

	d.mu.Lock()
	defer d.mu.Unlock()

	policy, ok := d.policies[id]
	if !ok {
		return nil
	}

	// 記録されている fire wall id をもとに fire wall ルールを削除します。
	for _, fwId := range policy.FwRuleIds {
		// もしルールがすでに存在しない場合は何もしません(error は返ってこないので処理を継続できます)
		if err := d.fwManager.Delete(fwId); err != nil {
			return err
		}
	}

	delete(d.policies, id)

	return nil
}

// Run 関数は DoS protector のメインロジックです
// 毎秒 bpf マップから {address, protocol, type} 別の受信パケット数を取得して
// セットされたポリシーをみて制限を越したものがないか検査します。
func (d *DoSProtector) Run(ctx context.Context) error {

	// この変数にイテレーションした結果の key, value が順次格納されます。
	var (
		key   identifier
		value uint64
	)

	// 1 秒毎にシグナルを出してくれます.
	ticker := time.NewTicker(time.Second)

	for {
		select {
		// 1 秒ごとにこの処理が呼ばれます。
		case <-ticker.C:
			// counterMap(dosp_counter bpf map) の要素をすべて調べます。
			entries := d.counterMap.Iterate()
			// MapIterator から読み取れる限り値を読み出します。
			for entries.Next(&key, &value) {
				d.logger.DebugCtx(ctx, "iterate entries of dosp_counter", slog.Any("key", key), slog.Uint64("value", value))
				// 前回の処理で記録していたパケット数を取り出す or 初回であれは 0 で初期化します。
				var prevCount uint64
				c, ok := d.counter[key]
				if !ok {
					d.logger.InfoCtx(ctx, "insert new DoS protection identifier", slog.Any("identifier", key))
					d.counter[key] = value
					prevCount = 0
				} else {
					prevCount = c
					d.counter[key] = value
				}
				// 適用されているポリシーに対してこの identifier がマッチするかを検査します。
				for _, policy := range d.policies {
					protocol, err := protocols.NewTransportProtocol(uint32(key.Protocol))
					if err != nil {
						d.logger.ErrorCtx(ctx, "invalid transport protocol", err, slog.Int("protocol", int(key.Protocol)), slog.Int("type", int(key.Type)))
						continue
					}
					policy.mu.Lock()
					if policy.Protocol == protocol && policy.Type == protocols.TcpFlag(key.Type) {
						// policy にマッチするパケットが計測されているので制限すべきかどうかを判断します。
						if policy.Limit < value-prevCount {
							// 制限を超えていたときは fire wall にルールを追加してパケットをドロップするようにする.
							d.logger.InfoCtx(ctx, "exceeded the limit. trigger DoS protection", slog.Any("policy", policy), slog.Uint64("received count", value))
							addr, err := protocols.IpAddrFromLe(key.Address)
							if err != nil {
								d.logger.ErrorCtx(ctx, "failed to parse IP address", err, slog.Uint64("address", uint64(key.Address)))
								continue
							}
							prefix, err := addr.Prefix(32)
							if err != nil {
								d.logger.ErrorCtx(ctx, "failed to get prefix", err, slog.String("address", addr.String()))
								continue
							}
							// fire wall のルールを作成します。
							rule := firewall.FWRule{
								Prefix:      prefix,
								ToSrcPort:   0,
								FromSrcPort: 0,
								FromDstPort: 0,
								ToDstPort:   0,
								Protocol:    protocol,
							}
							// fire wall のルールを適用します。
							id, err := d.fwManager.Set(&rule)
							if err != nil {
								d.logger.ErrorCtx(ctx, "failed to add a new fire wall rule", err, slog.Any("policy", policy), slog.Any("rule", rule))
								continue
							}
							// パケットの制限をかけたのでルール id を記録して、ポリシーのステータスを変更します。
							policy.FwRuleIds = append(policy.FwRuleIds, id)
							policy.Status = PolicyStatusTriggered
						}
					}
					policy.mu.Unlock()
				}
			}
			// もしマップのイテレーションにエラーが発生した場合はログに出力してそのまま処理を継続します。
			if err := entries.Err(); err != nil {
				d.logger.ErrorCtx(ctx, "failed to iterate dosp_counter map", err)
			}
		// Run の呼び出し元の処理が終了したとき通知されて Run のループ処理を正常に終了させます。
		case <-ctx.Done():
			d.logger.InfoCtx(ctx, "stopping DoS protector loop")
			return nil
		}
	}
}
