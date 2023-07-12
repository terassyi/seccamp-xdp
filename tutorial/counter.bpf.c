#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17 

u32 tcp_counter = 0;
u32 udp_counter = 0;
u32 icmp_counter = 0;

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
	if (iph->protocol == IP_PROTO_ICMP) {
		icmp_counter++;
	} else if (iph->protocol == IP_PROTO_TCP) {
		tcp_counter++;
	} else if (iph->protocol == IP_PROTO_UDP) {
		udp_counter++;
	}

	bpf_printk("icmp: %d tcp: %d udp: %d", icmp_counter, tcp_counter, udp_counter);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
