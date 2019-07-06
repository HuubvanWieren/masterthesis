#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

struct packetFields {
    uint32_t IPsrc;
    uint32_t IPdst;
//    uint32_t IPsrc;
    uint16_t totl;
//    uint8_t ttl;
    uint8_t proto;
    uint16_t srcPort;
    uint16_t dstPort;
    long cntr;
};

//BPG_PROG_ARRAY(progs, 1)
BPF_TABLE_SHARED("percpu_hash", int, struct packetFields, packeth, 1);
BPF_TABLE("percpu_hash", uint32_t, int, iplist, 2048);

int xdp_prog(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    //header structs
    struct ethhdr *ethh = data;
    struct iphdr *iph = NULL;

    uint64_t offset = sizeof(*ethh);

    if (data + offset > data_end)
        return XDP_DROP;

    if(ethh->h_proto != htons(ETH_P_IP)){
        return XDP_DROP;
    }

    iph = data + offset;
    if ((void*)&iph[1] > data_end)
        return XDP_DROP;
    offset += iph->ihl*4;

    int *value;
    value = iplist.lookup(&(iph->saddr));
    if(value){
        *value += 1;
        bpf_trace_printk("is dit pakket gedropt of niet?", value);
        return XDP_DROP;
    }

    return XDP_PASS;
}