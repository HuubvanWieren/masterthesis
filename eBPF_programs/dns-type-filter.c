#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

/*
    DNS Header for packet forging
    Copyright (C) 2016 unh0lys0da

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

struct dnshdr{
	uint16_t id;
	uint16_t rd:1;
	uint16_t tc:1;
	uint16_t aa:1;
	uint16_t opcode:4;
	uint16_t qr:1;
	uint16_t rcode:4;
	uint16_t zero:3;
	uint16_t ra:1;
	uint16_t qcount;	/* question count */
	uint16_t ancount;	/* Answer record count */
	uint16_t nscount;	/* Name Server (Autority Record) Count */ 
	uint16_t adcount;	/* Additional Record Count */
};

struct question_after_name_s { 
        uint16_t type;
        uint16_t cls;
};


//BPG_PROG_ARRAY(progs, 1)

//BPF_TABLE("percpu_hash", uint16_t, int, srcports, 1024); // 131072 8388608
//BPF_PERF_OUTPUT(events);

int Number(char w[][20]) {
    int i, j, counter = 0;
    for (i = 0; i < 4; i++) {
        char c, last = ' ';
        for (j = 0; (c = w[i][j]) != '\0'; j++) {
            if (last == ' ' && c != ' ')
                counter++;
            last = c;
        }
    }
    return counter;
}



int xdp_prog(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
	
    //header structs
    struct ethhdr *ethh = data;
    struct iphdr *iph = NULL;
	struct tcphdr *tcp   = NULL;
    struct udphdr *udp   = NULL;
	struct dnshdr *dns = NULL;
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
		dstPort = udp->dest;
	} else {
		return XDP_PASS;
	}
	//events.perf_submit(ctx, &srcPort, sizeof(srcPort));
	
	dstPort = (dstPort>>8) | (dstPort<<8);
	srcPort = (srcPort>>8) | (srcPort<<8);

	if(srcPort == 53 || dstPort == 53){
		dns = data + offset;
		offset += sizeof(*dns);
		if(data + offset > data_end)
			return XDP_PASS;
		
		const size_t namepos = 2*6; // name position in bytes form the beginning of the DNS query, this should be equal to 'sizeof(struct ethhdr) + sizeof(struct iphdr)   +  sizeof(struct udphdr) + sizeof(struct dnshdr)-1 ' from your code
		char *name = (char*)&data[namepos]; // the pointer name should point to the location in packet after namepos bytes
		const size_t packetlen = data_end - data; // I guess this is received DNS query length obtained from libcap
		const size_t querytypeandclasslen = 2*2; // length of the query type and query class, should be equal to sizeof(struct question_after_name_s)
		const size_t namelen = packetlen - namepos - querytypeandclasslen;

		struct question_after_name_s *ptr = data + namepos + namelen;//(void*)&data[namepos + namelen];
		//or
		//struct question_after_name_s *ptr = (void*)&data[];
		

		return XDP_DROP;
	}

    return XDP_PASS;
}
