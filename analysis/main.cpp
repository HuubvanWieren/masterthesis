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

int main(int argc, char *argv[])
{
	// open a pcap file for reading
	pcpp::PcapFileReaderDevice reader(argv[1]);
	if (!reader.open()) {
		printf("Error opening the pcap file\n");
		exit(1);
	}
	
	int overlap = atoi(argv[2]);
	std::string attackkey = argv[3];
	
	int tn = 0;
	int fn = 0;
	pcpp::RawPacket rawPacket;
	while (reader.getNextPacket(rawPacket)) {
		//parse the raw packet into a parsed packet
		pcpp::Packet parsedPacket(&rawPacket);

		// verify the packet is IPv4
		if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
			pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
			pcpp::iphdr *iph = NULL;
			iph = ipLayer->getIPv4Header();
			if (iph->headerChecksum == 0x3412) {
				fn += 1;
			}
			else if (iph->headerChecksum == 0xCDAB) {
				tn += 1;
			}
		}
	}
	// close the file
	reader.close();
	
	std::ofstream myfile;
    myfile.open ("results.csv", std::ios_base::app);
	
	int total = tn+fn;
	cout << "Total packets: " << total << "\n";
	int tp = 1582358 - fn;
	int fp = 1582358 - tn;
	
	cout << "True negatives: " << tn << "\n";
    cout << "True positives: " << tp << "\n";
    cout << "False positives: " << fp << "\n";
	cout << "False negatives: " << fn << "\n";
	
	float tpr = (float) tp / 1582358;
	float fpr = (float) fp / 1582358;
	float tnr = (float) tn / 1582358;
	float fnr = (float) fn / 1582358;
	
	cout << "True negative rate: " << tnr << "\n";
    cout << "True positive rate: " << tpr << "\n";
    cout << "False positives rate: " << fpr << "\n";
	cout << "False negatives rate: " << fnr << "\n";
	
	myfile << attackkey << "," << overlap << "," << total << "," << tp << "," << fp << "," << tn << "," << fn << "\n";
	myfile.close();
	return 0;
}
