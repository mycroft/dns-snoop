//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

#include <linux/pkt_cls.h>
#include <linux/udp.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long int u64;

#define DNS_PORT 53
#define DNS_MAX_SIZE 4096

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u16 len;
    u8 payload[DNS_MAX_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

u16 inline min(u16 a, u16 b) {
    if (a > b) {
        return b;
    } else {
        return a;
    }
}

SEC("tc")
int tc_dns_snoop(struct __sk_buff *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    void *payload;
    struct event *e;

    struct iphdr *ip;
    struct ipv6hdr *ip6;

    struct udphdr *udp;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_IPV6)) {
        return TC_ACT_OK;
    }

    switch (eth->h_proto) {
        case bpf_htons(ETH_P_IP):
            ip = (void *)(eth + 1);
            if ((void *)(ip + 1) > data_end) {
                return TC_ACT_OK;
            }

            if (ip->protocol != IPPROTO_UDP) {
                return TC_ACT_OK;
            }

            udp = (void *)(ip + 1);

            break;

        case bpf_htons(ETH_P_IPV6):
            ip6 = (void *)(eth + 1);
            if ((void *)(ip6 + 1) > data_end) {
                return TC_ACT_OK;
            }

            if (ip6->nexthdr != IPPROTO_UDP) {
                return TC_ACT_OK;
            }

            udp = (void *)(ip6 + 1);
            break;
    }

    // uudp
    payload = (void *)(udp + 1);

    if (payload > data_end || (bpf_ntohs(udp->dest) != DNS_PORT && bpf_ntohs(udp->source) != DNS_PORT)) {
        return TC_ACT_OK;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return TC_ACT_OK;
    }

    e->len = bpf_ntohs(udp->len);
    bpf_probe_read_kernel(e->payload, min(sizeof(e->payload), e->len), (void *)(udp + 1));

    bpf_ringbuf_submit(e, 0);

    bpf_printk("udp len: %d", bpf_ntohs(udp->len));

    return TC_ACT_OK;
}