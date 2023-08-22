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

	if (rule == NULL) {
		return 0;
	}

	u8 rule_prorocol = rule->protocol;
	// パケットのプロトコルがルールの対象プロトコルとマッチしていなければ 0
	if (rule_prorocol != protocol && rule_prorocol != 0) {
		return 0;
	}

	// icmp パケットの場合は port がないのでここに入って来ます。
	if (protocol == IP_PROTO_ICMP) {
		return 1;
	}

	u16 dst = bpf_htons(dst_port);
	u16 src = bpf_htons(src_port);
	// rule の from/to_port がどちらも 0 のときはすべてのポートが対象なので 1 を返します。
	if ((rule->from_dst_port == 0) && (rule->to_dst_port == 0)) {
		return 1;
	}

	// src_port が from_src_port =< src_port <= to_src_port の関係にあるとき 1 を返します。
	if ((src >= rule->from_src_port) && (rule->to_src_port >= src)) {
		return 1;
	}

	// dst_port が from_dst_port <= dst_port <= to_dst_port の関係にあるとき 1 を返します。
	if ((dst >= rule->from_dst_port) && (rule->to_dst_port >= dst)) {
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

// backend 構造体をコピーします
void copy_backend(struct backend *src, struct backend *dst) {
	dst->id = src->id;
	dst->ifindex = src->ifindex;
	dst->status = src->status;
	__builtin_memcpy(dst->src_macaddr, src->src_macaddr, ETH_ALEN);
	__builtin_memcpy(dst->dst_macaddr, src->dst_macaddr, ETH_ALEN);
	dst->dst_ipaddr = src->dst_ipaddr;
}

// connection_info 構造体をコピーします
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

// Ingress の TCP コネクションの状態を処理します。
static inline void process_tcp_state_ingress(struct tcphdr *tcph, struct connection_info *conn_info) {
	// エントリーが取れた場合は connection_info 構造体にキャストします。
	conn_info->counter++;
	bpf_printk("existing backend id is %d. count up to %d", conn_info->id, conn_info->counter);

	if (tcph->fin) {
		// TCP FIN フラグがセットされていたとき、Opening or Established -> Closing か Closing -> Closed に遷移する必要があります。
		if (conn_info->status == Opening || conn_info->status == Established) {
			conn_info->status = Closing;
		} else if (conn_info->status == Closing) {
			conn_info->status = Closed;
		} else {
			// その他の状態で FIN がきたときは Closed に遷移します。
			conn_info->status = Closed;
		}
	} else if (tcph->rst) {
		// TCP RST フラグがセットされていたときは問答無用で Closed に遷移します。
		conn_info->status = Closed;
	} else {
		// その他のフラグに関してはここではコネクションは継続とみなします。
	}
}

// Egress の TCP コネクションの状態を処理します。
static inline void process_tcp_state_egress(struct tcphdr *tcph, struct connection_info *conn_info) {

	// TCP フラグと保存されているコネクションの状態をみてコネクションを処理します。
	if (tcph->syn) {
		// SYN フラグが戻りパケットについているとき、Opening -> Established と遷移します。
		if (conn_info->status == Opening) {
			conn_info->status = Established;
		}
	} else if (tcph->rst) {
		// RST フラグがセットされているときはどのような状態でも Closed に遷移します。
		conn_info->status = Closed;

	} else if (tcph->fin) {
		// FIN フラグがついているときは Opening or Established -> Closing か Closing -> Closed に遷移します。
		if (conn_info->status == Opening || conn_info->status == Established) {
			conn_info->status = Closing;
		} else if (conn_info->status == Closing) {
			conn_info->status = Closed;
		} else {
			// 他の状態のときも Closed に遷移します。
			conn_info->status = Closed;
		}
	}
}

// UDP コネクションの状態を処理します。
// UDP の conntrack エントリーは状態を管理しないのでここでは counter をカウントアップするだけです。
// Ingress でのみ呼び出されます。
static inline void process_udp_state(struct udphdr *udph, struct connection_info *conn_info) {
	conn_info->counter++;
}

// Ingress の TCP パケットの書き換えを行います。
// Ingress の TCP パケットは選択したバックエンドに転送するために宛先アドレスを VIP からバックエンドのアドレスに書き換えます。
// それに伴って IP/TCP のチェックサムを再計算します。
static inline void update_tcp_packet_ingress(struct iphdr *iph, struct tcphdr *tcph, u32 addr) {
	// tcp checksum を再計算します。
	// tcp checksum は tcp ヘッダを含めたデータ全体と送信元アドレス、宛先アドレス、プロトコル番号と tcp データを含めたパケット長を計算対象とします。
	// このチェックサム計算のみに使うデたの塊を疑似ヘッダ(peseudo header) といいます。
	// ここではアドレス書き換えの差分のみ計算できるようにしています。
	u16 old_tcp_check = tcph->check;
	tcph->check = ipv4_csum_update_u32(tcph->check, iph->daddr, addr);

	// dnat のために ip header の daddr を書き換えます。
	u32 old_daddr = iph->daddr;
	iph->daddr = addr;
	// ip checksum を再計算します。
	// iph->check = ipv4_csum_update_u16(iph->check, old_tcp_check, tcph->check);
	iph->check = ipv4_csum_update_u32(iph->check, old_daddr, iph->daddr);
}

// Ingress の UDP パケットの書き換えを行います。
// Ingress の UDP パケットは選択したバックエンドに転送するために宛先アドレスを VIP からバックエンドのアドレスに書き換えます。
// それに伴って IP/UDP のチェックサムを再計算します。
static inline void update_udp_packet_ingress(struct iphdr *iph, struct udphdr *udph, u32 addr) {
	// UDP checksum を再計算します。
	// UDP checksum は tcp ヘッダを含めたデータ全体と送信元アドレス、宛先アドレス、プロトコル番号と tcp データを含めたパケット長を計算対象とします。
	// このチェックサム計算のみに使うデたの塊を疑似ヘッダ(peseudo header) といいます。
	// ここではアドレス書き換えの差分のみ計算できるようにしています。
	u16 old_udp_check = udph->check;
	udph->check = ipv4_csum_update_u32(udph->check, iph->daddr, addr);
	u32 old_addr = iph->daddr;
	// dnat のために ip header の daddr を書き換えます。
	iph->daddr = addr;
	iph->check = ipv4_csum_update_u32(iph->check, old_addr, iph->daddr);
}

// Egress の TCP パケットの書き換えを行います。
// Egress のパケットはバックエンドからクライアントに送られるときに送信元アドレスを VIP にして送信されなければなりません。
// それに伴って IP/TCP のチェックサムを再計算します。
static inline void update_tcp_packet_egress(struct iphdr *iph, struct tcphdr *tcph, u32 addr) {
	// tcp checksum を再計算します。
	// ここでは 戻りパケットの src address を vip に書き換えています。
	u16 old_tcp_check = tcph->check;
	tcph->check = ipv4_csum_update_u32(tcph->check, iph->saddr, addr);

	// reverse SNAT のために ip header の saddr を書き換えます。
	u32 old_saddr = iph->saddr;
	iph->saddr = addr;
	// ip checksum を再計算します。
	// iph->check = ipv4_csum_update_u16(iph->check, old_tcp_check, tcph->check);
	iph->check = ipv4_csum_update_u32(iph->check, old_saddr, iph->saddr);
}

// Egress の UDP パケットの書き換えを行います。
// Egress のパケットはバックエンドからクライアントに送られるときに送信元アドレスを VIP にして送信されなければなりません。
// それに伴って IP/UDP のチェックサムを再計算します。
static inline void update_udp_packet_egress(struct iphdr *iph, struct udphdr *udph, u32 addr) {
	// udp checksum を再計算します。
	u16 old_udp_check = udph->check;
	udph->check = ipv4_csum_update_u32(udph->check, iph->saddr, addr);

	// reverse SNAT のために ip header の saddr を書き換えます。
	u32 old_saddr = iph->saddr;
	iph->saddr = addr;
	// ip checksum を再計算します。
	// iph->check = ipv4_csum_update_u16(iph->check, old_udp_check, udph->check);
	iph->check = ipv4_csum_update_u32(iph->check, old_saddr, iph->saddr);

}

// connection_info 造体を初期化します。
static inline void new_connection_info(struct connection_info *conn_info, u32 backend_id, u32 ifindex, u8 mac_addr[6], u16 state) {
	conn_info->counter = 1;
	conn_info->id = backend_id;
	conn_info->index = ifindex;
	__builtin_memcpy(conn_info->src_macaddr, mac_addr, ETH_ALEN);
	conn_info->status = state;
}

// Ingress TCP パケット用の connection 構造体を作成します。
// ここで作成した connection 構造体は conntrack に登録するために使われます。
static inline void build_tcp_connection_ingress(struct connection *conn, struct iphdr *iph, struct tcphdr *tcph) {
	conn->src_addr = iph->saddr;
	conn->dst_addr = iph->daddr;
	conn->src_port = tcph->source;
	conn->dst_port = tcph->dest;
	conn->protocol = iph->protocol;
}

// Ingress UDP パケット用の connection 構造体を作成します。
// ここで作成した connection 構造体は conntrack に登録するために使われます。
static inline void build_udp_connection_ingress(struct connection *conn, struct iphdr *iph, struct udphdr *udph) {
	conn->src_addr = iph->saddr;
	conn->dst_addr = iph->daddr;
	conn->src_port = udph->source;
	conn->dst_port = udph->dest;
	conn->protocol = iph->protocol;
}

// Egress TCP パケットの connection 構造体を作成します。
// ここで作成した connection 構造体は conntrack に登録したエントリーを引くために利用されるので
// 宛先アドレスを addr として明示的に渡しています(ここでは VIP を期待しています)。
static inline void build_tcp_connection_egress(struct connection *conn, struct iphdr *iph, struct tcphdr *tcph, u32 addr) {
	conn->src_addr = iph->daddr;
	conn->dst_addr = addr;
	conn->src_port = tcph->dest;
	conn->dst_port = tcph->source;
	conn->protocol = iph->protocol;
}

// Egress UDP パケットの connection 構造体を作成します。
// ここで作成した connection 構造体は conntrack に登録したエントリーを引くために利用されるので
// 宛先アドレスを addr として明示的に渡しています(ここでは VIP を期待しています)。
static inline void build_udp_connection_egress(struct connection *conn, struct iphdr *iph, struct udphdr *udph, u32 addr) {
	conn->src_addr = iph->daddr;
	conn->dst_addr = addr;
	conn->src_port = udph->dest;
	conn->dst_port = udph->source;
	conn->protocol = iph->protocol;
}

// ロードバランサーの TCP パケットを処理する部分の関数です。
static inline int handle_tcp_ingress(struct tcphdr *tcph, struct iphdr *iph, u8 src_macaddr[6], struct backend *target) {

	if (tcph == NULL) {
		return -1;
	}

	// conntrack のエントリーを取得するために connection 構造体を宣言します。
	struct connection conn;
	__builtin_memset(&conn, 0, sizeof(conn));
	build_tcp_connection_ingress(&conn, iph, tcph);

	void *r = bpf_map_lookup_elem(&conntrack, &conn);

	if (r) {
		// エントリーが取れた場合は connection_info 構造体にキャストします。
		struct connection_info *conn_info = r;
		process_tcp_state_ingress(tcph, conn_info);

		// backend id からバックエンドの情報を取り出します。
		void *res = bpf_map_lookup_elem(&backend_info, &conn_info->id);
		if (!res) {
			bpf_printk("backend is not found: %d", conn_info->id);
			return -1;
		}
		struct backend *b = res;

		update_tcp_packet_ingress(iph, tcph, b->dst_ipaddr);

		// target backend を引数に渡したポインタに書き込みます。
		copy_backend(b, target);

		return 0;
	}

	// もし conntrack にエントリーがない場合は新しいコネクションとして扱います。

	int selection_result = select_backend();
	if (selection_result != 0) {
		return selection_result;
	}

	bpf_printk("handle new tcp connection. backend is %d", selected_backend_id);

	// selected_backend_id 変数に選ばれたバックエンドが格納されているのでこの値を利用して backend を引きます。
	void *res = bpf_map_lookup_elem(&backend_info, &selected_backend_id);
	if (res == NULL) {
		bpf_printk("selected backend id(%d) is not registered in backend_info map", selected_backend_id);
		return -1;
	}

	struct backend *b = res;

	struct connection_info conn_info;
	__builtin_memset(&conn_info, 0, sizeof(conn_info));
	new_connection_info(&conn_info, b->id, b->ifindex, src_macaddr, Opening);

	// 新しいコネクションに対して TCP SYN フラグがついていない場合コネクションは確立されていないので無視します。
	if (tcph->syn != 1) {
		bpf_printk("new connection packet must be set syn flag");
		return -1;
	}

	// conntrack エントリーを保存します
	int update_res = bpf_map_update_elem(&conntrack, &conn, &conn_info, 0);
	if (update_res != 0) {
		return update_res;
	}

	update_tcp_packet_ingress(iph, tcph, b->dst_ipaddr);

	// target backend を引数に渡したポインタに書き込みます。
	copy_backend(b, target);

	return 0;
}

// ロードバランサーの UDP パケットを処理する部分の関数です。
static inline int handle_udp_ingress(struct udphdr *udph, struct iphdr *iph, u8 src_macaddr[6], struct backend *target) {

	if (udph == NULL) {
		return -1;
	}
	
	// conntrack のエントリーを取得するために connection 構造体を宣言します。
	struct connection conn;
	__builtin_memset(&conn, 0, sizeof(conn));
	build_udp_connection_ingress(&conn, iph, udph);

	void *r = bpf_map_lookup_elem(&conntrack, &conn);
	if (r) {
		// エントリーが取れた場合は connection_info 構造体にキャストします。
		struct connection_info *conn_info = r;

		process_udp_state(udph, conn_info);

		// backend id からバックエンドの情報を取り出します。

		void *res = bpf_map_lookup_elem(&backend_info, &conn_info->id);
		if (!res) {
			bpf_printk("backend is not found: %d", conn_info->id);
			return -1;
		}
		struct backend *b = res;

		update_udp_packet_ingress(iph, udph, b->dst_ipaddr);

		// target backend を引数に渡したポインタに書き込みます。
		copy_backend(b, target);
		

		return 0;
	}
	// もし conntrack にエントリーがない場合は新しいコネクションとして扱います。

	struct connection_info conn_info;
	__builtin_memset(&conn_info, 0, sizeof(conn_info));

	int selection_result = select_backend();
	if (selection_result != 0) {
		bpf_printk("failed to select backend. errno is %d", selection_result);
		return selection_result;
	}

	bpf_printk("handle new udp flow. backend is %d", selected_backend_id);

	// selected_backend_id 変数に選ばれたバックエンドが格納されているのでこの値を利用して backend を引きます。
	void *res = bpf_map_lookup_elem(&backend_info, &selected_backend_id);
	if (res == NULL) {
		bpf_printk("selected backend fd(%d) is not registered in backend_info map", selected_backend_id);
		return -1;
	}

	struct backend *b = res;

	new_connection_info(&conn_info, b->id, b->ifindex, src_macaddr, NotTcp);

	// 新しい conntrack エントリーを保存します
	int update_res = bpf_map_update_elem(&conntrack, &conn, &conn_info, 0);
	if (update_res != 0) {
		return update_res;
	}

	update_udp_packet_egress(iph, udph, b->dst_ipaddr);
	
	// target backend を引数に渡したポインタに書き込みます。
	copy_backend(b, target);

	return 0;
}

// ロードバランサーの外向きの TCP パケットを処理する部分の関数です。
static inline int handle_tcp_egress(struct tcphdr *tcph, struct iphdr *iph, struct upstream *us, struct connection_info *target) {

	// egress の TCP パケットの処理を記述します。

	// conntrack を引くための構造体を宣言します。
	struct connection conn;
	__builtin_memset(&conn, 0, sizeof(conn));
	build_tcp_connection_egress(&conn, iph, tcph, us->ipaddr);

	// conntrack のエントリーを引きます。
	void *conn_res = bpf_map_lookup_elem(&conntrack, &conn);
	if (conn_res == NULL) {
		return -1;
	}

	struct connection_info *conn_info = conn_res;

	process_tcp_state_egress(tcph, conn_info);

	update_tcp_packet_egress(iph, tcph, us->ipaddr);

	// connection_info をコピーします。
	copy_connection_info(conn_info, target);

	return 0;
}

// ロードバランサーの外向きの UDP パケットを処理する部分の関数です。
static inline int handle_udp_egress(struct udphdr *udph, struct iphdr *iph, struct upstream *us, struct connection_info *target) {

	// conntrack を引くための構造体を宣言します。
	struct connection conn;
	__builtin_memset(&conn, 0, sizeof(conn));
	build_udp_connection_egress(&conn, iph, udph, us->ipaddr);

	// conntrack のエントリーを引きます。
	void *conn_res = bpf_map_lookup_elem(&conntrack, &conn);
	if (!conn_res) {
		return -1;
	}
	struct connection_info *info = conn_res;

	update_udp_packet_egress(iph, udph, us->ipaddr);

	// connection_info をコピーします。
	copy_connection_info(info, target);

	return 0;
}

// この関数は entrypoint 関数から tail call で呼び出されます
SEC("xdp_count")
int count(struct xdp_md *ctx) {

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
	
	u32 *c = bpf_map_lookup_elem(&counter, &l4_protocol);
	if (c) {
		(*c)++;
		bpf_printk("increment counter %d", c);
	} else {
		bpf_map_update_elem(&counter, &l4_protocol, &initial_value, 0);
	}
	
	bpf_tail_call(ctx, &calls_map, TAIL_CALLED_FUNC_FIREWALL);

	bpf_printk("must not be reached");
	return XDP_PASS;
}

SEC("xdp_firewall")
int firewall(struct xdp_md *ctx) {

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

	data += sizeof(*iph);

	struct network nw = {
		.prefix_len = 32,
		.address = iph->saddr,
	};

	// LPM Trie マップを検索します
	u16 *ids = bpf_map_lookup_elem(&adv_rulematcher, &nw);
	if (ids) {
		// 返ってきたポインタを u16 の配列にキャストします
		for (int i = 0; i < FIRE_WALL_RULE_MAX_SIZE_PER_NETWORK; i++) {
			if (ids[i] == 0) {
				break;
			}

			u32 id = (u32)ids[i];


			// map から id をキーとして rule をとりだします
			void *rule_res = bpf_map_lookup_elem(&adv_rules, &id);
			if (rule_res == NULL) {
				continue;
			}
			struct fw_rule *rule = rule_res;

			// パケットのプロトコルを判別して port などの必要な値をとりだしてルールにマッチするか確かめます
			int res = 0;
			if (iph->protocol == IP_PROTO_ICMP) {
				res = fw_match(rule, iph->protocol, 0, 0);
			} else if (iph->protocol == IP_PROTO_TCP) {
				struct tcphdr *tcph = data;
				if (data + sizeof(*tcph) > data_end) {
					return XDP_ABORTED;
				}

				res = fw_match(rule, iph->protocol, tcph->source, tcph->dest);
			} else if (iph->protocol == IP_PROTO_UDP) {
				struct udphdr *udph = data;
				if (data + sizeof(*udph) > data_end) {
					return XDP_ABORTED;
				}
				res = fw_match(rule, iph->protocol, udph->source, udph->dest);
			}
			// もしルールにマッチしていたら drop_counter の値をカウントアップしてパケットをドロップします
			if (res == 1) {
				bpf_printk("matched the rule: %d", id);
				u64 *c = bpf_map_lookup_elem(&drop_counter, &rule->id);
				if (c) {
					(*c)++;
				} else {
					u64 init_value = 1;
					bpf_map_update_elem(&drop_counter, &rule->id, &init_value, 0);
				}
				return XDP_DROP;
			}
		}
	}

	bpf_tail_call(ctx, &calls_map, TAIL_CALLED_FUNC_DOS_PROTECTOR);
	return XDP_PASS;
}

SEC("xdp_dos_protector")
int dos_protector(struct xdp_md *ctx) {

	// DoS protection の機能では XDP プログラムでは DoS 攻撃かの判断はしません。
	// ここでは単にどのようなパケットがどのくらい受信されたかをカウントしてマップに保存します。
	// カウントした値を control plane (Go のプログラム) の方から検査して受信したパケットの数に不審な点があれば、
	// 一つ前の Fire wall にルールを追加してパケットの受信をブロックします。

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

	data += sizeof(*iph);

	// L4 プロトコルを判別する
	u8 l4_protocol = iph->protocol;
	u32 src_addr = iph->saddr;

	struct dos_protection_identifier ident;
	// 構造体のメンバをすべて 0 で初期化しています。
	// 初期化をしっかりやらないと verifier に怒られます。
	__builtin_memset(&ident, 0, sizeof(ident));
	ident.address = src_addr;
	ident.protocol = l4_protocol;

	if (l4_protocol == IP_PROTO_ICMP) {
		ident.packet_type = 0;

	} else if (l4_protocol == IP_PROTO_TCP) {
		struct tcphdr *tcph = data;
		if (data + sizeof(*tcph) > data_end) {
			return XDP_ABORTED;
		}
		
		// tcp パケットの場合はフラグをチェックする
		if (tcph->fin) {
			ident.packet_type = TCP_FLAG_FIN;
		} else if (tcph->syn) {
			ident.packet_type = TCP_FLAG_SYN;
		} else if (tcph->rst) {
			ident.packet_type = TCP_FLAG_RST;
		} else if (tcph->psh) {
			ident.packet_type = TCP_FLAG_PSH;
		} else if (tcph->urg) {
			ident.packet_type = TCP_FLAG_URG;
		} else if (tcph->ece) {
			ident.packet_type = TCP_FLAG_ECE;
		} else if (tcph->cwr) {
			ident.packet_type = TCP_FLAG_CWR;
		// ack はほぼすべてのパケットについているので比較を最後にしています
		} else if (tcph->ack) {
			ident.packet_type = TCP_FLAG_ACK;
		}
	} else if (l4_protocol == IP_PROTO_UDP) {
		ident.packet_type = 0;

	} else {
		// icmp, tcp, udp プロトコル以外のパケットは無視する
		return XDP_ABORTED;
	}

	u64 *c = bpf_map_lookup_elem(&dosp_counter, &ident);
	if (c) {
		(*c)++;
	} else {
		u64 init = 1;
		bpf_map_update_elem(&dosp_counter, &ident, &init, 0);
	}

	bpf_tail_call(ctx, &calls_map, TAIL_CALLED_FUNC_LB_INGRESS);

	// ここには到達しません。
	return XDP_PASS;
}

SEC("xdp_lb_ingress")
int lb_ingress(struct xdp_md *ctx) {

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

	data += sizeof(*iph);

	u8 l4_protocol = iph->protocol;

	// ロードバランサーでは TCP と UDP プロトコルを対象とします。
	if (l4_protocol != IP_PROTO_TCP && l4_protocol != IP_PROTO_UDP) {
		return XDP_PASS;
	}

	struct backend target;
	__builtin_memset(&target, 0, sizeof(target));

	if (l4_protocol == IP_PROTO_TCP) {
		struct tcphdr *tcph = data;
		if (data + sizeof(*tcph) > data_end) {
			return XDP_ABORTED;
		}
		int res = handle_tcp_ingress(tcph, iph, ethh->h_source, &target);
		if (res != 0) {
			// 何かしらのエラーが発生した場合は kernel にパスします。
			return XDP_PASS;
		}
	} else if (l4_protocol == IP_PROTO_UDP) {
		struct udphdr *udph = data;
		if (data + sizeof(*udph) > data_end) {
			return XDP_ABORTED;
		}
		int res = handle_udp_ingress(udph, iph, ethh->h_source, &target);
		if (res != 0) {
			// 何かしらのエラーが発生した場合は kernel にパスします。
			return XDP_PASS;
		}
	}

	return redirect(ethh, target.src_macaddr, target.dst_macaddr, target.ifindex);
}

SEC("xdp_lb_egress")
int lb_egress(struct xdp_md *ctx) {

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

	data += sizeof(*iph);

	u8 l4_protocol = iph->protocol;

	// ロードバランサーでは TCP と UDP プロトコルを対象とします。
	if (l4_protocol != IP_PROTO_TCP && l4_protocol != IP_PROTO_UDP) {
		return XDP_PASS;
	}


	// upstream の情報をマップから取得します。
	u32 u = 0;
	void *upstream_res = bpf_map_lookup_elem(&upstream_info, &u);
	if (!upstream_res) {
		// 値が取れなかったらエラーです。
		bpf_printk("failed to get upstream information");
		return XDP_PASS;
	}
	struct upstream *us = upstream_res;

	// connection_info を受け取るための構造体を宣言します。
	struct connection_info target;
	__builtin_memset(&target, 0, sizeof(target));

	if (l4_protocol == IP_PROTO_TCP) {
		struct tcphdr *tcph = data;
		if (data + sizeof(*tcph) > data_end) {
			return XDP_ABORTED;
		}
		int res = handle_tcp_egress(tcph, iph, us, &target);
		if (res != 0) {
			// 何かしらのエラーが発生した場合は kernel にパスします。
			bpf_printk("tcp egress handle error %d", res);
			return XDP_PASS;
		}
	} else if (l4_protocol == IP_PROTO_UDP) {
		struct udphdr *udph = data;
		if (data + sizeof(*udph) > data_end) {
			return XDP_ABORTED;
		}
		int res = handle_udp_egress(udph, iph, us, &target);
		if (res != 0) {
			// 何かしらのエラーが発生した場合は kernel にパスします。
			bpf_printk("udp egress handle error %d", res);
			return XDP_PASS;
		}
	}

	return redirect(ethh, us->macaddr, target.src_macaddr, us->ifindex);
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
		// counter() に tail call します。
		// その後、counter -> firewall -> dos_protector -> lb_ingress の順に処理されます。
		bpf_tail_call(ctx, &calls_map, TAIL_CALLED_FUNC_COUNT);
	} else {
		struct backend *info = res;

		// 情報が取得できたときは lb_egress() に tail call します。
		bpf_tail_call(ctx, &calls_map, TAIL_CALLED_FUNC_LB_EGRESS);

	}


	// tail call したあとは戻り先の関数に復帰することはないのでこの部分には実行されないはずです
	bpf_printk("This line must not be reached.");

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
