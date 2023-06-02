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

// struct bar {
//     __u16 id;
//     __u64 seid;
//     __u16 pkt_count;
//     __u32 ndbuf_ip;
// };

/* For TX-traffic redirect requires net_device ifindex to be in this devmap */
BPF_MAP_DEF(buf_flows) = {
    .map_type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
};
BPF_MAP_ADD(buf_flows);

// struct ndbuf {
//     __u32 saddr;    
// 	unsigned char dst[ETH_ALEN];
// 	unsigned char src[ETH_ALEN];
// };

BPF_MAP_DEF(ndbuf_info) = {
    .map_type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
};
BPF_MAP_ADD(ndbuf_info);

// static int buffer_handle(struct xdp_md *ctx, struct iphdr *ip,
//     struct ethhdr *eth)
// {
//     void *data = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;
//     struct bar *bar;
//     struct ndbuf *ndbuf;
//     u32 dst_addr, csum = 0;
//     u16 offset;    

//     // offset = ntohs(ip->ihl) * 4;
//     offset = ip->ihl * 4;
//     if ((void *)ip + offset > data_end) {
//         bpf_printk("Failed to parse IPv4\n");
//         return XDP_ABORTED;
//     }
    
//     // IP destination address is UE address
//     dst_addr = ip->daddr;
//     bar = bpf_map_lookup_elem(&buf_flows, &dst_addr);
//     if (!bar) {
//         return XDP_PASS;
//     }

//     ip->tos = 0;
//     csum = 0;
//     // ipv4_csum(ip, sizeof(struct iphdr), &csum);
//     ndbuf = bpf_map_lookup_elem(&ndbuf_info, &bar->ndbuf_ip);
//     if (!ndbuf) {
//         return XDP_DROP;
//     }

//     bar->pkt_count++;
//     ip->saddr = ndbuf->saddr;
//     ip->daddr = bar->ndbuf_ip;
//     __builtin_memcpy(eth->h_source, ndbuf->src, ETH_ALEN);
//     __builtin_memcpy(eth->h_dest, ndbuf->dst, ETH_ALEN);

//     return XDP_REDIRECT;
// }

// static int gtp5g_eth_handle(struct xdp_md *ctx)
// {
//     void *data = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;
//     struct ethhdr *eth = data;
//     u16 eth_type;
//     u64 offset;
//     int ret = XDP_PASS;

//     offset = sizeof(*eth);
//     if ((void *)eth + offset > data_end) {
//         bpf_printk("Failed to parse the packet off: %llu", offset);
//         return XDP_DROP;
//     }
   
//     // eth_type = htons(eth->h_proto);
//     eth_type = eth->h_proto;
//     switch (eth_type) {
//     case ETH_P_IP:
//         ret = buffer_handle(ctx, (struct iphdr *)((void *)eth + offset), eth);
//         break;
//     default:
//         bpf_printk("Cannot parse L2: L3off:%llu proto:0x%x\n", offset, eth_type);
//     }

//     return ret;
// }

SEC("xdp")
int gtp5g_buf_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Only IPv4 supported for this example
    struct ethhdr *ether = data;
    if (data + sizeof(*ether) > data_end) {
        return XDP_ABORTED;
     }
    if (ether->h_proto == 0x08U) {  // htons(ETH_P_IP) -> 0x08U
        data += sizeof(*ether);
        struct iphdr *ip = data;
        if (data + sizeof(*ip) > data_end) {
             return XDP_ABORTED;
        }
        // Increase counter in "protocols" eBPF map
        // __u32 proto_index = ip->protocol;
        // __u64 *counter = bpf_map_lookup_elem(&protocols, &proto_index);
        // if (counter) {
        //   (*counter)++;
        // }
    }

  return XDP_PASS;
    // return gtp5g_eth_handle(ctx);
}

char _license[] SEC("license") = "GPL";