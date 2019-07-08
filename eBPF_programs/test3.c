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
    struct ipv6hdr  *ip6   = NULL;
    struct tcphdr   *tcp   = NULL;
    struct udphdr   *udp   = NULL;
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

    uint32_t toblock;
    toblock = iph->saddr;
    int *value;
    value = iplist.lookup(&toblock);
    bpf_trace_printk("%u\n",toblock);
    if(value){
        *value += 1;
        bpf_trace_printk("is dit pakket gedropt of niet?", value);
        return XDP_DROP;
    }

    int key = 0;
    struct packetFields p = {};
    struct packetFields *pkt = packeth.lookup_or_init(&key, &p);

    if(pkt==NULL){
        bpf_trace_printk("wahed this shouldn't be possible\n");
        return XDP_DROP; //not possible?
    }

//    pkt->IPdst = -1;
//    pkt->IPsrc = -1;
//    pkt->proto = -1;
//    pkt->IPsrc = iph->daddr;
    pkt->IPsrc = iph->saddr;
    pkt->IPdst = iph->daddr;
    pkt->totl = iph->tot_len;
//    pkt->ttl = iph->ttl;
    pkt->proto = iph->protocol;



    if(iph->protocol == IPPROTO_TCP) { //TCP
        tcp = data + offset;
        offset += sizeof(*tcp);
        if(data + offset + sizeof(*tcp) > data_end)
            return XDP_DROP;
        pkt->srcPort = tcp->source;
        pkt->dstPort = tcp->dest;
    } else if(iph->protocol == 17) { //UDP
        udp = data + offset;
        offset += sizeof(*udp);
        if(data + offset + sizeof(*udp) > data_end)
            return XDP_DROP;
        pkt->srcPort = udp->source;
        pkt->dstPort = udp->dest;
    } else {
        pkt->srcPort = 0;
        pkt->dstPort = 0;
    }

    pkt->cntr += 1;
    return XDP_PASS;
}