#include <bpf/bpf_helpers.h>

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
