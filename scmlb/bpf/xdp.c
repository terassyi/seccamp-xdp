#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"
#include "tail_call.h"

#define ETH_P_IP 0x0800

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17 

#define TCP_FLAG_FIN 1
#define TCP_FLAG_SYN 2
#define TCP_FLAG_RST 4
#define TCP_FLAG_PSH 8
#define TCP_FLAG_ACK 16
#define TCP_FLAG_URG 32
#define TCP_FLAG_ECE 64
#define TCP_FLAG_CWR 128

// ルールに対して与えたプロトコル番号とポートが対象のとき 1 を返して、それ以外の場合は 0 を返す関数です
int fw_match(struct fw_rule *rule, u8 protocol, u16 src_port, u16 dst_port) {

	u8 rule_prorocol = rule->protocol;
	// パケットのプロトコルがルールの対象プロトコルとマッチしていなければ 0
	if (rule_prorocol != protocol && rule_prorocol != 0) {
		return 0;
	}

	// icmp パケットの場合は port がないのでここに入って来ます。
	if (src_port == 0) {
		return 1;
	}

	// rule の from/to_port がどちらも 0 のときはすべてのポートが対象なので 1 を返します。
	if ((rule->from_src_port == 0) && (rule->to_src_port == 0)) {
		return 1;
	}

	// src_port が from_src_port =< src_port <= to_src_port の関係にあるとき 1 を返します。
	if ((src_port >= rule->from_src_port) && (rule->to_src_port >= src_port)) {
		return 1;
	}

	// dst_port が from_dst_port <= dst_port <= to_dst_port の関係にあるとき 1 を返します。
	if ((dst_port >= rule->from_dst_port) && (rule->to_dst_port >= dst_port)) {
		return 1;
	}

	return 0;
}

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
	
	// ここに firewall のロジックを記述します。

	bpf_tail_call(ctx, &calls_map, TAIL_CALLED_FUNC_DOS_PROTECTOR);
	return XDP_PASS;
}

SEC("xdp_dos_protector")
int dos_protector(struct xdp_md *ctx) {

	// DoS protection の機能では XDP プログラムでは DoS 攻撃かの判断はしません。
	// ここでは単にどのようなパケットがどのくらい受信されたかをカウントしてマップに保存します。
	// カウントした値を control plane (Go のプログラム) の方から検査して受信したパケットの数に不審な点があれば、
	// 一つ前の Fire wall にルールを追加してパケットの受信をブロックします。

	bpf_printk("hello from scmlb dos protector!");

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
