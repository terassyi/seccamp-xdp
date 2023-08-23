#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17 

// このプログラムのカウンタの値は以下のようにして確認できます
/*
$ sudo bpftool map | grep protocols // このコマンドで対象の protocols map の id をみつける
$ sudo bpftool map dump id <みつけた id>
*/

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 3);
} protocols SEC(".maps");

SEC("xdp")
int counter(struct xdp_md *ctx) {

	// パケットのバイト列のはじまりのポインタ (data) とおわりのポインタ (data_end) を定義する
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	// Ethernet header の構造体にパケットのデータをマッピングする
	struct ethhdr *ethh = data;
	// Ethenet header の長さがパケットのバイト列より長くないことを確認する
	// 無効なアドレスにアクセスしないことを確認している
	if (data + sizeof(*ethh) > data_end) {
		return XDP_ABORTED;
	}

	// IPv4 パケットだけを集計の対象とする
	if (bpf_ntohs(ethh->h_proto) != ETH_P_IP) {
		return XDP_PASS;
	}

	data += sizeof(*ethh);

	// Ethernet payload を IPv4 パケットにマッピングする
	struct iphdr *iph = data;
	if (data + sizeof(*iph) > data_end) {
		return XDP_ABORTED;
	}

	// L4 のプロトコルに合わせてカウントアップする
	u32 l4_protocol = (u32)iph->protocol;
	u32 initial_value = 1;
	
	u32 *c = bpf_map_lookup_elem(&protocols, &l4_protocol);
	if (c) {
		(*c)++;
		bpf_printk("increment counter %d", *c);
	} else {
		bpf_map_update_elem(&protocols, &l4_protocol, &initial_value, 0);
	}
	
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
