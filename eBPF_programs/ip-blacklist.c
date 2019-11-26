#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

//BPG_PROG_ARRAY(progs, 1)
BPF_TABLE("percpu_hash", uint32_t, uint16_t, iplist, 6524288);

int xdp_prog(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    //header structs
    struct ethhdr *ethh = data;
    struct iphdr *iph = NULL;

    uint64_t offset = sizeof(*ethh);

    if (data + offset > data_end)
        return XDP_PASS;

    if(ethh->h_proto != htons(ETH_P_IP)){
        return XDP_PASS;
    }

    iph = data + offset;
    if ((void*)&iph[1] > data_end)
        return XDP_PASS;
    offset += iph->ihl*4;

    int *value;
    value = iplist.lookup(&(iph->saddr));
    if(value){
        *value += 1;
        return XDP_DROP;
    }

    return XDP_PASS;
}
