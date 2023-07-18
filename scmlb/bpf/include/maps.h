#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#include "scmlb.h"

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

// TPM_TRIE は Longest Prefix Match Trie の略でキーにネットワークプレフィックスを与えることで longest prefix match をカーネル側で処理してくれます。
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	// key は uint64 の値でないといけないようです
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct fw_rule));
	__uint(max_entries, 1028);
	// LPM_TRIE ではこのフラグを指定しないとロードできません
	__uint(map_flags, BPF_F_NO_PREALLOC);
} rules SEC(".maps");


//
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2056);
} drop_counter SEC(".maps");
