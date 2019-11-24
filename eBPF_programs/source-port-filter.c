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

BPF_TABLE("percpu_hash", uint16_t, int, srcports, 8388608); // 131072 8388608
BPF_PERF_OUTPUT(events);


int xdp_prog(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
	
    //header structs
    struct ethhdr *ethh = data;
    struct iphdr *iph = NULL;
	struct tcphdr *tcp   = NULL;
    struct udphdr *udp   = NULL;
	uint8_t proto;
	uint16_t srcPort;
	uint16_t dstPort;
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
		
	proto = iph->protocol;

	if(proto == 17) { //UDP
		udp = data + offset;
		offset += sizeof(*udp);
		if(data + offset + sizeof(*udp) > data_end)
			return XDP_PASS;
		srcPort = udp->source;
	} else {
		return XDP_PASS;
	}
	//events.perf_submit(ctx, &srcPort, sizeof(srcPort));
	bpf_trace_printk("Source port=%d\n", srcPort);

	srcPort = (srcPort>>8) | (srcPort<<8);
		
	int *srcportmatch;
	srcportmatch = srcports.lookup(&srcPort);
	if(srcportmatch){
		*srcportmatch += 1;
		return XDP_DROP;
	}

    return XDP_PASS;
}
