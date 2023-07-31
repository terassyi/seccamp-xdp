#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#include "scmlb.h"

#define FIRE_WALL_RULE_MAX_SIZE_PER_NETWORK 16
#define BACKEND_MAX_SIZE 16

// tail call 用の特別なマップです
// Go 言語のユーザーランドのプログラムから要素を追加して tail call する関数を登録します。
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 10);
} calls_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 3);
} counter SEC(".maps");

// LPM_TRIE は Longest Prefix Match Trie の略でキーにネットワークプレフィックスを与えることで longest prefix match をカーネル側で処理してくれます。
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	// key は uint64 の値でないといけないようです
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct fw_rule));
	__uint(max_entries, 1028);
	// LPM_TRIE ではこのフラグを指定しないとロードできません
	__uint(map_flags, BPF_F_NO_PREALLOC);
} rules SEC(".maps");

// advanced な fire wall のための LPM_TRIE のマップです。
// ネットワークプレフィックス address/prefix を uint64 に埋め込んだ値をキーとして
// uint16 の fire wall id の列をバリューとして持ちます。
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u16) * FIRE_WALL_RULE_MAX_SIZE_PER_NETWORK);
	__uint(max_entries, 1028);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} adv_rulematcher SEC(".maps");

// advanced な fire wall のための rule id をキーとして port, protocol などのルールを value とするマップです。
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct fw_rule));
	__uint(max_entries, 1028);
} adv_rules SEC(".maps");


// fire wall でドロップされたパケットをカウントして保存するマップです。
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2056);
} drop_counter SEC(".maps");

// DoS protector のためのパケット種類別の数をカウントするためのマップです。
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct dos_protection_identifier));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2056);
} dosp_counter SEC(".maps");

// backend のデバイスを登録してリダイレクトするためのマップです。
// XDP_REDIRECT でパケットをリダイレクトするときにこのマップから値が引かれます。
// 実際には bpf_redirect() というヘルパー関数で呼び出します。
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1028);
} redirect_dev_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, BACKEND_MAX_SIZE);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} backend_ifindex SEC(".maps");

// ロードバランサーのバックエンドの情報を XDP プログラムに伝えるためのマップです。
// バックエンドの id をキーとして、
// そのインターフェースに割り当てられているバックエンド情報を値として持ちます。
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct backend));
	__uint(max_entries, BACKEND_MAX_SIZE);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} backend_info SEC(".maps");

// ロードバランサーの upstream の情報を格納するマップです。
// 基本的に upstream の情報はひとつしかないのでエントリー数は 1 です。
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct upstream));
	__uint(max_entries, 1);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} upstream_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct connection));
	__uint(value_size, sizeof(struct connection_info));
	__uint(max_entries, 2056);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack SEC(".maps");

// ロードバランサーのバックエンド選択のラウンドロビンのテーブルです。
// キーは配列のインデックスです。
// バリューは backend の id です。
// BPF プログラムの方ではグローバル変数として前回選択したインデックスを保存していて、次はそのインデックスからバックエンドを選択します。
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, BACKEND_MAX_SIZE);
	// __uint(pinning, LIBBPF_PIN_BY_NAME);
} rr_table SEC(".maps");
