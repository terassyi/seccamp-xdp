#include "vmlinux.h"

struct network {
	u32 prefix_len;
	u32 address;
};

struct fw_rule {
	u32 id;
	u16 from_port;
	u16 to_port;
	u32 protocol;
};

struct dos_protection_identifier {
	u32 address;
	u8 protocol;
	u8 packet_type;
};
