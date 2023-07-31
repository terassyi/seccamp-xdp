#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"
#include "tail_call.h"
#include "csum.h"

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
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

// ロードバランサーのバックエンド選択方式でラウンドロビンを利用するときに
// 前回の選択結果のバックエンド id を記録しておくためのグローバル変数です。
u32 selected_backend_id = 0;
u32 selected_backend_index = 0;

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

// 受信したパケットを対象のインターフェースにリダイレクトするための関数です。
// 送信元・宛先のMAC アドレスをともに書き換えて対象に届くようにしています。
// ここで、Ethernet フレームのチェックサムは NIC 側で計算してくれるので XDP プログラム内で計算する必要はありません。
static inline int redirect(struct ethhdr *eth, u8 *s_mac, u8 *d_mac, u32 ifindex) {
	__builtin_memcpy(eth->h_dest, d_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, s_mac, ETH_ALEN);
	return bpf_redirect_map(&redirect_dev_map, ifindex, 0);
}

void copy_backend(struct backend *src, struct backend *dst) {
	dst->id = src->id;
	dst->ifindex = src->ifindex;
	dst->status = src->status;
	__builtin_memcpy(dst->src_macaddr, src->src_macaddr, ETH_ALEN);
	__builtin_memcpy(dst->dst_macaddr, src->dst_macaddr, ETH_ALEN);
	dst->dst_ipaddr = src->dst_ipaddr;
}

void copy_connection_info(struct connection_info *src, struct connection_info *dst) {
	dst->counter = src->counter;
	dst->id = src->id;
	dst->index = src->index;
	dst->status = src->status;
	__builtin_memcpy(dst->src_macaddr, src->src_macaddr, ETH_ALEN);
}

// 新しいコネクションを処理するバックエンドを選択するための関数です。
// 選択したバックエンドの値は グローバル変数の selected_backend_id に格納されます。
static inline int select_backend() {

	// rr_table から selected_backend_id + 1 の値を引きます。
	u32 next = selected_backend_index + 1;
	u32 *backend_id = bpf_map_lookup_elem(&rr_table, &next);
	if (backend_id && *backend_id > 0) {
		// 値が取れたときはその backend id を利用して backend_info マップを引いて通信を転送します。
		bpf_printk("select backend. id is %d", *backend_id);
		selected_backend_index = next;
		selected_backend_id = *backend_id;
	} else {
		// もし取れなかったときは rr_table 配列の最後に到達しているということなので折り返して index 0 で探索します。
		u32 next = 0;
		u32 *backend_id2 = bpf_map_lookup_elem(&rr_table, &next);
		if (!backend_id2 || *backend_id2 == 0) {
			// ここでも 0 だったとき、rr_table には値が格納されていないとみなしてエラーで返ります。
			return -1;
		}
		// 取れた場合はその値を selected_backend_id とする。
		bpf_printk("select backend. id is %d", *backend_id2);
		selected_backend_index = next;
		selected_backend_id = *backend_id2;
	}

	return 0;
}

// ロードバランサーの TCP パケットを処理する部分の関数です。
static inline int handle_tcp_ingress(struct tcphdr *tcph, struct iphdr *iph, u8 src_macaddr[6], struct backend *target) {

	// ingress の TCP パケットの処理を記述します。

	if (tcph == NULL) {
		return -1;
	}

	return 0;
}

// ロードバランサーの UDP パケットを処理する部分の関数です。
static inline int handle_udp_ingress(struct udphdr *udph, struct iphdr *iph, u8 src_macaddr[6], struct backend *target) {

	// ingress の UDP パケットの処理を記述します。

	if (udph == NULL) {
		return -1;
	}

	return 0;
}

// ロードバランサーの外向きの TCP パケットを処理する部分の関数です。
static inline int handle_tcp_egress(struct tcphdr *tcph, struct iphdr *iph, struct upstream *us, struct connection_info *target) {

	// egress の TCP パケットの処理を記述します。
	return 0;
}

// ロードバランサーの外向きの UDP パケットを処理する部分の関数です。
static inline int handle_udp_egress(struct udphdr *udph, struct iphdr *iph, struct upstream *us, struct connection_info *target) {

	// egress の UDP パケットの処理を記述します。

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

SEC("xdp_lb_ingress")
int lb_ingress(struct xdp_md *ctx) {

	// ここに upstream から入ってきたパケットの処理を記述します。

	// 実際は XDP_REDIRECT を返すことになります。
	return XDP_PASS;

}

SEC("xdp_lb_egress")
int lb_egress(struct xdp_md *ctx) {

	// ここに backend から返ってきたパケットの処理を記述します。
	bpf_printk("hello from scmlb egress");

	// 実際は XDP_REDIRECT を返すことになります。
	return XDP_PASS;
}

SEC("xdp_entry")
int entrypoint(struct xdp_md *ctx) {
	
	// 受信したパケットがどのインターフェースからやってきたかを調べます。
	u32 ingress_ifindex = ctx->ingress_ifindex;



	// 受信したインターフェースがロードバランサーのバックエンドとして登録されているかどうかを検査します。
	void *res = bpf_map_lookup_elem(&backend_ifindex, &ingress_ifindex);
	if (res == NULL) {
		// インターフェースのインデックスからバックエンドの情報が取得できなかったときは
		// アップストリームから来たものとします。
		// lb_ingress() に tail call します。
		bpf_printk("receive from upstream");
		bpf_tail_call(ctx, &calls_map, TAIL_CALLED_FUNC_LB_INGRESS);
	} else {
		struct backend *info = res;

		// 情報が取得できたときは lb_egress() に tail call します。
		bpf_printk("receive from backend %d", info->id);
		bpf_tail_call(ctx, &calls_map, TAIL_CALLED_FUNC_LB_EGRESS);

	}


	// tail call したあとは戻り先の関数に復帰することはないのでこの部分には実行されないはずです
	bpf_printk("This line must not be reached.");

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
