#define KBUILD_MODNAME "gtp5g_buf"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "bpf_helpers.h"

#if 0
struct nvme_entry {
    __be32 uip; /* UPF Buffer MAC address */
    __be64 umac; /* UPF Buffer MAC address */
    int uifindex; /* UPF Buffer link index */
    __be64 nmac; /* NVMe link index */
};

struct bar_entry {
    u16 pktcnt; /* Current packet count */
};

struct buf_entry {
    __be32 ip; /* UE IP Address*/
    u16 bid; /* BAR ID */
    u16 pktcnt; /* Total packet count */   
	__be32 nip; /* NVMe IP address */   
};

struct {
	// __uint(type, BPF_MAP_TYPE_HASH);
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__type(key, __be32); /* NVMe IP Address */
	__type(value, struct nvme_entry);
	__uint(max_entries, 64);
} gtp5g_nvme_table SEC(".maps");

struct {
	// __uint(type, BPF_MAP_TYPE_HASH);
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__type(key, u16); /* BAR ID */
	__type(value, struct bar_entry);
	__uint(max_entries, 64);
} gtp5g_bar_table SEC(".maps");

struct {
	// __uint(type, BPF_MAP_TYPE_HASH);
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__type(key, __be32); /* UE IP Address */
	__type(value, struct buf_entry);
	__uint(max_entries, 64);
} gtp5g_buf_table SEC(".maps");
#endif

#if 0
static int buffer_handle(struct xdp_md *ctx, struct iphdr *ip,
    struct ethhdr *eth)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct buf_entry *buf_entry;
    struct bar_entry *bar_entry;
    struct nvme_entry *nvme_entry;
    u32 addr;
    u16 bid;

    // offset = ntohs(ip->ihl) * 4;
    if ((void *)ip + 20 > data_end) {
        bpf_printk("Failed to parse IPv4\n");
        return XDP_ABORTED;
    }
    
    // Buffer Table
    addr = ip->daddr;
    buf_entry = bpf_map_lookup_elem(&gtp5g_buf_table, &addr);
    if (!buf_entry) {
        return XDP_PASS;
    }
    bid = buf_entry->bid;

    // BAR Table
    bar_entry = bpf_map_lookup_elem(&gtp5g_bar_table, &bid);
    if (!bar_entry) {
        return XDP_PASS;
    }
    bar_entry->pktcnt++;

    // NVMe Table
    addr = buf_entry->nip;
    nvme_entry = bpf_map_lookup_elem(&gtp5g_nvme_table, &addr);
    if (!nvme_entry) {
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
#endif

static int buffer_handle(struct xdp_md *ctx, struct iphdr *ip,
    struct ethhdr *eth)
{
#if 0
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct buf_entry *buf_entry;
    struct bar_entry *bar_entry;
    struct nvme_entry *nvme_entry;
    u32 addr;
    u16 bid;

    // offset = ntohs(ip->ihl) * 4;
    if ((void *)ip + 20 > data_end) {
        bpf_printk("Failed to parse IPv4\n");
        return XDP_ABORTED;
    }
    
    // Buffer Table
    addr = ip->daddr;
    buf_entry = bpf_map_lookup_elem(&gtp5g_buf_table, &addr);
    if (!buf_entry) {
        return XDP_PASS;
    }
    bid = buf_entry->bid;

    // BAR Table
    bar_entry = bpf_map_lookup_elem(&gtp5g_bar_table, &bid);
    if (!bar_entry) {
        return XDP_PASS;
    }
    bar_entry->pktcnt++;

    // NVMe Table
    addr = buf_entry->nip;
    nvme_entry = bpf_map_lookup_elem(&gtp5g_nvme_table, &addr);
    if (!nvme_entry) {
        return XDP_PASS;
    }

    // TODO: Packet Count

    ip->tos = 0;
    // csum = 0;
    // ipv4_csum(ip, sizeof(struct iphdr), &csum);
    // __builtin_memcpy(eth->h_source, saddr, ETH_ALEN);
    // __builtin_memcpy(eth->h_dest, daddr, ETH_ALEN);
#endif

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