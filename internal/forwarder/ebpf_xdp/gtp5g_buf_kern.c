// #define KBUILD_MODNAME "gtp5g_buf"
// #include <uapi/linux/bpf.h>
// #include <linux/byteorder/generic.h>
// #include <linux/in.h>
// #include <linux/if_ether.h>
// #include <linux/if_packet.h>
// #include <linux/if_vlan.h>
// #include <linux/ip.h>
// #include <linux/ipv6.h>
// #include <net/checksum.h>

#include "bpf_helpers.h"

typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short  u16;

// Ethernet header
// #include <linux/if_ether.h>
#define ETH_ALEN    6
#define ETH_P_IP    0x0800      /* Internet Protocol packet */
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
// #include <linux/ip.h>
struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));

/* For TX-traffic redirect requires net_device ifindex to be in this devmap */
/* BAR Flow table */
BPF_MAP_DEF(flow_seid) = {
    .map_type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};
BPF_MAP_ADD(flow_seid);

// NVMe Downlink Buffer IP (32b)
BPF_MAP_DEF(seid_nip) = {
    .map_type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};
BPF_MAP_ADD(seid_nip);

// TX-Redirect link identifier and packet count
BPF_MAP_DEF(seid_idpkt) = {
    .map_type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};
BPF_MAP_ADD(seid_idpkt);

static int buffer_handle(struct xdp_md *ctx, struct iphdr *ip,
    struct ethhdr *eth)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    u32 *seid, *nip;
    u64 *id_pkt;
    u32 seid_key;
    u32 addr;

    // offset = ntohs(ip->ihl) * 4;
    if ((void *)ip + 20 > data_end) {
        bpf_printk("Failed to parse IPv4\n");
        return XDP_ABORTED;
    }
    
    // IP destination address is UE address
    addr = ip->daddr;
    seid = bpf_map_lookup_elem(&flow_seid, &addr);
    if (!seid) {
        return XDP_PASS;
    }
    seid_key = *seid;

    // Get the NVMe system ip address
    nip = bpf_map_lookup_elem(&seid_nip, &seid_key);
    if (!nip) {
        return XDP_PASS;
    }

    id_pkt = bpf_map_lookup_elem(&seid_idpkt, &seid_key);
    if (!id_pkt) {
        return XDP_PASS;
    }

    // TODO: Packet Count

    ip->tos = 0;
    // csum = 0;
    // ipv4_csum(ip, sizeof(struct iphdr), &csum);
    // __builtin_memcpy(eth->h_source, saddr, ETH_ALEN);
    // __builtin_memcpy(eth->h_dest, daddr, ETH_ALEN);

    return XDP_REDIRECT;
}

static int gtp5g_eth_handle(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    u16 eth_type;
    u64 offset;
    int ret = XDP_PASS;

    offset = sizeof(*eth);
    if ((void *)eth + offset > data_end) {
        bpf_printk("Failed to parse the packet off: %llu", offset);
        return XDP_DROP;
    }
   
    // eth_type = htons(eth->h_proto);
    if (eth->h_proto != 0x08) {
        ret = buffer_handle(ctx, (struct iphdr *)((void *)eth + offset), eth);
    } else {
        bpf_printk("Cannot parse L2: L3off:%llu proto:0x%x\n", offset, eth_type);
    }

    return ret;
}

SEC("xdp")
int gtp5g_buf_prog(struct xdp_md *ctx)
{
    bpf_printk("Received a packet\n");
    return gtp5g_eth_handle(ctx);
}
// int gtp5g_buf_prog(struct xdp_md *ctx)
// {
//     void *data_end = (void *)(long)ctx->data_end;
//     void *data = (void *)(long)ctx->data;

//     // Only IPv4 supported for this example
//     struct ethhdr *ether = data;
//     if (data + sizeof(*ether) > data_end) {
//         return XDP_ABORTED;
//      }
//     if (ether->h_proto == 0x08U) {  // htons(ETH_P_IP) -> 0x08U
//         data += sizeof(*ether);
//         struct iphdr *ip = data;
//         if (data + sizeof(*ip) > data_end) {
//              return XDP_ABORTED;
//         }
//         // Increase counter in "protocols" eBPF map
//         // __u32 proto_index = ip->protocol;
//         // __u64 *counter = bpf_map_lookup_elem(&protocols, &proto_index);
//         // if (counter) {
//         //   (*counter)++;
//         // }
//     }
//     return XDP_PASS;
// }

char _license[] SEC("license") = "GPL";