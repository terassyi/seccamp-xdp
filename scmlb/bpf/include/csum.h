#include "vmlinux.h"
#include <bpf/bpf_endian.h>

static inline u16 ipv4_csum_update_u16(u16 csum, u16 old_val, u16 new_val) {
	u32 a = ~bpf_ntohs(csum) & 0x0000ffff;
	u32 b = bpf_ntohs(new_val) & 0x0000ffff;
	u32 c = ~bpf_ntohs(old_val) & 0x0000ffff;
	u32 sum = a + b + c;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return ~bpf_htons(sum);
}

static inline u16 ipv4_csum_update_u32(u16 csum, u32 old_val, u32 new_val) {
	u16 old_val_head = old_val >> 16;
	u16 new_val_head = new_val >> 16;
	u16 old_val_tail = old_val;
	u16 new_val_tail = new_val;
	csum = ipv4_csum_update_u16(csum, old_val_head, new_val_head);
	return ipv4_csum_update_u16(csum, old_val_tail, new_val_tail);
}

static inline __u16 csum_fold_helper(__u64 csum) {
	int i;
#pragma unroll
	for (i = 0; i < 4; i++) {
		if (csum >> 16) {
			csum = (csum & 0xffff) + (csum >> 16);
		}
	}
	return ~csum;
}

static inline void ipv4_csum_inline(void *iph, __u64 *csum) {
	__u16 *next_iph_u16 = (__u16 *)iph;
	for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
		*csum += *next_iph_u16++;
	}
	*csum = csum_fold_helper(*csum);
}

static inline __u16 checksum(__u16 *buf, __u32 bufsize) {
	__u32 sum = 0;
	while (bufsize > 1) {
		sum += *buf;
		buf++;
		bufsize -= 2;
	}
	if (bufsize == 1) {
		sum += *(__u8 *)buf;
	}
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}
