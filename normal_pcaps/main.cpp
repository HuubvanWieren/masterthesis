#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "fstream"
#include <vector>
#include <iterator>
#include <iostream>
#include <stdlib.h>
#include <string>

using namespace std;

//functions to get random element from vector (not used)
int random_int(int min, int max)
{
    return rand() % (max - min + 1) + min;
}

//template<class int>
int random_element(std::vector<uint32_t>& elements)
{
    return elements[random_int(0, elements.size() - 1)];
}

int main(int argc, char *argv[])
{
	//get percentage argument
	int f = atof(argv[1]);
    int i = 1;
	
	std::string textfilename = ".txt";
	textfilename.insert(0,argv[1]);
	
    //load corrent "file.txt" and uint32 IP addresses in a vector
    using isii = std::istream_iterator<uint32_t>;
    std::ifstream in{ textfilename};
	std::vector<uint32_t> ints{ isii{ in }, isii{} };

	//std::ifstream in("file.txt");
	
	int attacksize = ints.size();
	
	// can be used to print vector with ips:
    //for (int i=0; i<ints.size();i++){
    //	std::cout << ints.at(i) << ' ';
    //}

	std::string outputname = "normal.pcap";
	outputname.insert(6,argv[1]);
	//std::cout << "Follow this command: " << outputname;
	
    pcpp::PcapFileWriterDevice pcapWriter(outputname.c_str(), pcpp::LINKTYPE_ETHERNET);

    // try to open the file for writing
    if (!pcapWriter.open()) {
        printf("Cannot open output.pcap for writing\n");
        exit(1);
    }

    // open a pcap file for reading
    pcpp::PcapFileReaderDevice reader("bigFlows.pcap");
    if (!reader.open()) {
        printf("Error opening the pcap file\n");
        exit(1);
    }
    int i2 = 0;
    pcpp::RawPacket rawPacket;
	printf("%i\n",attacksize);
    while (reader.getNextPacket(rawPacket)) {
        i += 1;
        i = i % 1000;

        //parse the raw packet into a parsed packet
        pcpp::Packet parsedPacket(&rawPacket);

        // verify the packet is IPv4
        if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
            pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
//            ipLayer->setSrcIpAddress(pcpp::IPv4Address(std::string("123.2.1.6")));
            pcpp::iphdr *iph = NULL;
            iph = ipLayer->getIPv4Header();
            iph->headerChecksum = 0xcdab;
			srand(((unsigned)time(NULL))+i);
			int r = random_int(0,100);
            iph->ipDst = 687865866;
	if (f > r) {
                //ipLayer->setSrcIpAddress(pcpp::IPv4Address(random_element(ints)));
                ipLayer->setSrcIpAddress(pcpp::IPv4Address(ints[i2])); //assign new source IP address
                i2 += 1;
                i2 = i2 % attacksize;
            }
            pcapWriter.writePacket(rawPacket);
        }
    }
    // close the file
    reader.close();
    return 0;
}
