//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

#include <linux/pkt_cls.h>

#include <linux/tcp.h>
#include <linux/udp.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long int u64;

#define DNS_PORT 53
#define DNS_MAX_SIZE 4096

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u16 protocol;
    u8 layer_protocol;
    u16 len;
    u8 payload[DNS_MAX_SIZE];

    u8 v6_s_addr[16];
    u8 v6_d_addr[16];

    u8 v4_s_addr[4];
    u8 v4_d_addr[4];
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

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;

    u16 payload_len = 0;

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

            switch (ip->protocol) {
                case IPPROTO_UDP:
                    udp = (void *)(ip + 1);
                    payload_len = bpf_htons(ip->tot_len) - (ip->ihl*4) - sizeof(struct udphdr);
                    break;

                case IPPROTO_TCP:
                    tcp = (void *)(ip + 1);
                    payload_len = bpf_htons(ip->tot_len) - (ip->ihl*4) - (tcp->doff*4) - 2; // dns over tcp contains payload size.
                    break;
                default:
                    return TC_ACT_OK;
            }
            break;

        case bpf_htons(ETH_P_IPV6):
            ip6 = (void *)(eth + 1);
            if ((void *)(ip6 + 1) > data_end) {
                return TC_ACT_OK;
            }

            switch (ip6->nexthdr) {
                case IPPROTO_UDP:
                    udp = (void *)(ip6 + 1);
                    payload_len = bpf_htons(ip6->payload_len) - sizeof(struct udphdr);
                    break;
                case IPPROTO_TCP:
                    tcp = (void *)(ip6 + 1);
                    payload_len = bpf_htons(ip6->payload_len) - (tcp->doff*4) + 2;
                    break;

                default:
                    return TC_ACT_OK;
            }

            if (ip6->nexthdr != IPPROTO_UDP) {
                return TC_ACT_OK;
            }

            udp = (void *)(ip6 + 1);
            break;
    }

    if (udp != NULL) {
        payload = (void *)(udp + 1);
        if (payload > data_end || (bpf_ntohs(udp->dest) != DNS_PORT && bpf_ntohs(udp->source) != DNS_PORT)) {
            return TC_ACT_OK;
        }
    } else if (tcp != NULL) {
        payload = (void *)(tcp + 1);
        if (payload > data_end || (bpf_ntohs(tcp->dest) != DNS_PORT && bpf_ntohs(tcp->source) != DNS_PORT)) {
            return TC_ACT_OK;
        }

        if (!tcp->psh) {
            return TC_ACT_OK;
        }

        bpf_printk("tcp packet size:%d syn:%x ack:%x psh:%x payload_len:%d", data_end - payload, tcp->syn, tcp->ack, tcp->psh, payload_len);

    
        // return TC_ACT_OK;
    } else {
        return TC_ACT_OK;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return TC_ACT_OK;
    }

    e->protocol = eth->h_proto;
    switch (e->protocol) {
        case bpf_htons(ETH_P_IP):
            bpf_probe_read_kernel(
                e->v4_s_addr,
                sizeof(e->v4_s_addr),
                ((unsigned char*)(eth + 1)) + offsetof(struct iphdr, saddr)
            );

            bpf_probe_read_kernel(
                e->v4_d_addr,
                sizeof(e->v4_d_addr),
                ((unsigned char*)(eth + 1)) + offsetof(struct iphdr, daddr)
            );

            ip = (void *)(eth + 1);

            e->layer_protocol = ip->protocol;

            break;
        case bpf_htons(ETH_P_IPV6):
            bpf_probe_read_kernel(
                e->v6_s_addr,
                sizeof(e->v6_s_addr),
                ((unsigned char*)(eth + 1)) + offsetof(struct ipv6hdr, saddr)
            );
            bpf_probe_read_kernel(
                e->v6_d_addr,
                sizeof(e->v6_d_addr),
                ((unsigned char*)(eth + 1)) + offsetof(struct ipv6hdr, daddr)
            );

            ip6 = (void *)(eth + 1);

            bpf_printk("v6 next header: %d", ip6->nexthdr);
            break;
    }

    if (udp != NULL) {
        e->len = bpf_ntohs(udp->len);
        bpf_probe_read_kernel(e->payload, min(sizeof(e->payload), e->len), (void *)(udp + 1));
        // bpf_printk("udp len: %d", bpf_ntohs(udp->len));

    } else if (tcp != NULL) {
        e->len = payload_len;
        bpf_probe_read_kernel(e->payload, min(sizeof(e->payload), e->len), (void *)(ip + 1) + tcp->doff*4 + 2);
        bpf_printk("tcp len: %d ihl: %d offset:%d", payload_len, ip->ihl, tcp->doff);
    }

    bpf_ringbuf_submit(e, 0);

    return TC_ACT_OK;
}
