#include "vmlinux.h"

struct network {
	u32 prefix_len;
	u32 address;
};

struct fw_rule {
	u32 id;
	u16 from_src_port;
	u16 to_src_port;
	u16 from_dst_port;
	u16 to_dst_port;
	u32 protocol;
};

struct dos_protection_identifier {
	u32 address;
	u8 protocol;
	u8 packet_type;
};

// バックエンドの情報を登録する構造体です
struct backend {
	u32 id;
	u32 ifindex;
	u32 status;
	u8 src_macaddr[6];
	u8 dst_macaddr[6];
	u32 dst_ipaddr;
};

// upstream の情報を格納する構造体です。
struct upstream {
	u32 ipaddr; // ロードバランサーが待ち受ける VIP です。
	u16 ifindex; // VIP がついているデバイスではなく、実際にパケットを処理するデバイスの番号です。
	u8 macaddr[6]; // こちらも実際にパケット処理を行うデバイスの MAC アドレスです。
};

// 5-tuple (送信元アドレス/ポート、宛先アドレス/ポート、プロトコル) のセットの構造体です。
// ロードバランサがコネクションを一位に識別するためのキーとなります。
struct connection {
	u32 src_addr;
	u32 dst_addr;
	u16 src_port;
	u16 dst_port;
	u32 protocol;
};


// conntrack の connection をキーとして登録されるコネクションの情報を保存する構造体です。
struct connection_info {
	u32 backend_id;
	u32 index;
	u16 status; // TCP コネクションの状態を表します。
	u8 src_macaddr[6]; // 送信元の MAC アドレス
	u64 counter; // 受信したパケット数を記録するカウンター
};

// connection_info.status に格納するコネクションの状態を表す enum です。
// UDP の場合はコネクションではないので NotTcp を代入します。
// TCP の場合はコネクションの状態によって状態を遷移させます。
// 実際の TCP の状態より簡略化して表現しています。
enum ConnectionStatus {
	NotTcp,
	Opening,
	Established,
	Closing,
	Closed,
};

// ロードバランサーのバックエンドが利用可能な状態かどうかを示す enum です。
enum BackendStatus {
	Available,
	Unavailable,
};
