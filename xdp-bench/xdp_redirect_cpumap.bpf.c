/*  XDP redirect to CPUs via cpumap (BPF_MAP_TYPE_CPUMAP)
 *
 *  GPLv2, Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */
#include <bpf/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "hash_func01.h"

#define ETH_P_802_3_MIN 0x0600
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

/* Special map type that can XDP_REDIRECT frames to another CPU */
struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_cpumap_val));
} cpu_map SEC(".maps");

#define MAX_TARGET_CPUS 64
const volatile __u32 target_cpus[MAX_TARGET_CPUS] = { 3 };
const volatile __u32 nr_target_cpus = 1;

/* Helper parse functions */

static __always_inline bool parse_eth(struct ethhdr *eth, void *data_end,
				      __u16 *eth_proto, __u64 *l3_offset)
{
	if (__builtin_expect((void *)(eth + 1) > data_end, 0))
		return false;

	/* Skip non 802.3 Ethertypes */
	if (__builtin_expect(bpf_ntohs(eth->h_proto) < ETH_P_802_3_MIN, 0))
		return false;

	*eth_proto = bpf_ntohs(eth->h_proto);
	*l3_offset = sizeof(*eth);
	return true;
}

/* Hashing initval */
#define INITVAL 15485863

static __always_inline __u32 get_ipv4_hash_ip_pair(struct xdp_md *ctx,
						   __u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;
	__u32 cpu_hash;

	if (__builtin_expect(iph + 1 > data_end, 0))
		return 0;

	cpu_hash = iph->saddr + iph->daddr;

	if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
		struct udphdr *ports = (void *)(iph + 1);

		if (__builtin_expect(ports + 1 > data_end, 0))
			return 0;

		cpu_hash += ports->source + ports->dest;
	}

	cpu_hash = SuperFastHash((char *)&cpu_hash, 4, INITVAL + iph->protocol);

	return cpu_hash;
}

static __always_inline __u32 get_ipv6_hash_ip_pair(struct xdp_md *ctx,
						   __u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr *ip6h = data + nh_off;
	__u32 cpu_hash;

	if (__builtin_expect(ip6h + 1 > data_end, 0))
		return 0;

	cpu_hash =
		ip6h->saddr.in6_u.u6_addr32[0] + ip6h->daddr.in6_u.u6_addr32[0];
	cpu_hash +=
		ip6h->saddr.in6_u.u6_addr32[1] + ip6h->daddr.in6_u.u6_addr32[1];
	cpu_hash +=
		ip6h->saddr.in6_u.u6_addr32[2] + ip6h->daddr.in6_u.u6_addr32[2];
	cpu_hash +=
		ip6h->saddr.in6_u.u6_addr32[3] + ip6h->daddr.in6_u.u6_addr32[3];

	if (ip6h->nexthdr == IPPROTO_TCP || ip6h->nexthdr == IPPROTO_UDP) {
		struct udphdr *ports = (void *)(ip6h + 1);

		if (__builtin_expect(ports + 1 > data_end, 0))
			return 0;

		cpu_hash += ports->source + ports->dest;
	}

	cpu_hash = SuperFastHash((char *)&cpu_hash, 4, INITVAL + ip6h->nexthdr);

	return cpu_hash;
}

/* Load-Balance traffic based on hashing IP-addrs + L4-ports.  The
 * hashing scheme is symmetric, meaning swapping IP src/dest and
 * src/dest ports still hit same CPU.
 */
SEC("xdp")
int cpumap_l4_hash(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u16 eth_proto = 0;
	__u64 l3_offset = 0;
	__u32 cpu_hash;
	__u32 cpu_idx;

	if (__builtin_expect(!parse_eth(eth, data_end, &eth_proto, &l3_offset),
			     0))
		return XDP_PASS;

	switch (eth_proto) {
	case ETH_P_IP:
		cpu_hash = get_ipv4_hash_ip_pair(ctx, l3_offset);
		break;
	case ETH_P_IPV6:
		cpu_hash = get_ipv6_hash_ip_pair(ctx, l3_offset);
		break;
	default:
		cpu_hash = 0;
	}

	cpu_idx = cpu_hash % nr_target_cpus;
	return bpf_redirect_map(&cpu_map, target_cpus[cpu_idx], 0);
}

SEC("xdp/cpumap")
int cpumap_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
