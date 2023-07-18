#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"
#include "tail_call.h"

#define ETH_P_IP 0x0800

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17 

// この関数は entrypoint 関数から tail call で呼び出されます
SEC("xdp_count")
int count(struct xdp_md *ctx) {

	bpf_printk("hello from scmlb count!");
	
	// ここに packet counter のロジックを記述します。
	
	bpf_tail_call(ctx, &calls_map, TAIL_CALLED_FUNC_FIREWALL);

	bpf_printk("must not be reached");
	return XDP_PASS;
}

SEC("xdp_firewall")
int firewall(struct xdp_md *ctx) {

	bpf_printk("hello from scmlb firewall!");
	return XDP_PASS;
}

SEC("xdp_entry")
int entrypoint(struct xdp_md *ctx) {
	
	bpf_printk("hello from scmlb entrypoint!");

	bpf_tail_call(ctx, &calls_map, TAIL_CALLED_FUNC_COUNT);

	// tail call したあとは戻り先の関数に復帰することはないのでこの部分には実行されないはずです
	bpf_printk("This line must not be reached.");

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
