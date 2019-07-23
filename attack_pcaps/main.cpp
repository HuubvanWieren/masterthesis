#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "fstream"
#include <vector>
#include <iterator>
#include <iostream>
#include <stdlib.h>
#include <string>

int main(int argc, char *argv[])
{
	std::string outputname = "ddos.pcap";

    pcpp::PcapFileWriterDevice pcapWriter(outputname.c_str(), pcpp::LINKTYPE_ETHERNET);

    // try to open the file for writing
    if (!pcapWriter.open()) {
        printf("Cannot open output.pcap for writing\n");
        exit(1);
    }

    // open a pcap file for reading
//    std::string pcapfilename = ".pcap";
//	pcapfilename.insert(0,argv[1]);

    pcpp::PcapFileReaderDevice reader(argv[1]);
    if (!reader.open()) {
        printf("Error opening the pcap file\n");
        exit(1);
    }

    pcpp::RawPacket rawPacket;
    while (reader.getNextPacket(rawPacket)) {

        //parse the raw packet into a parsed packet
        pcpp::Packet parsedPacket(&rawPacket);

        // verify the packet is IPv4
        if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
            pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
            pcpp::iphdr *iph = NULL;
            iph = ipLayer->getIPv4Header();
            iph->headerChecksum = 0x3412;
            iph->ipDst = 838860810; //704643082; // 687865866;
            pcapWriter.writePacket(rawPacket);
        }
    }
    // close the file
    reader.close();
    return 0;
}
