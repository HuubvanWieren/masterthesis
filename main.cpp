#include "IPv4Layer.h"

#include "Packet.h"

#include "PcapFileDevice.h"

int main(int argc, char * argv[]) {
  int i = 1;
  int random[26];

  srand((unsigned)time(NULL));

  for (int i = 1; i < 26; i++)
  {
	random[i] = 1+ rand() % 10;
  }
  i = 0;
 
  pcpp::PcapFileWriterDevice pcapWriter("output.pcap", pcpp::LINKTYPE_ETHERNET);

  // try to open the file for writing
  if (!pcapWriter.open()) {
    printf("Cannot open output.pcap for writing\n");
    exit(1);
  }

  // open a pcap file for reading
  pcpp::PcapFileReaderDevice reader("output2.pcap");
  if (!reader.open()) {
    printf("Error opening the pcap file\n");
    exit(1);
  }

  pcpp::RawPacket rawPacket;
  while (reader.getNextPacket(rawPacket)) {
    i += 1;
    i = i%25;

    //printf("Couldn't read the first packet in the file\n");
    //return 1;

    //parse the raw packet into a parsed packet
    pcpp::Packet parsedPacket( & rawPacket);

    // verify the packet is IPv4
    if (parsedPacket.isPacketOfType(pcpp::IPv4)) {

      pcpp::IPv4Layer * ipLayer = parsedPacket.getLayerOfType < pcpp::IPv4Layer > ();
      //printf("%s\n", ipLayer->getSrcIpAddress().toString().c_str());

      if (random[i] > 7){
      ipLayer->setSrcIpAddress(pcpp::IPv4Address(std::string("123.2.1.6")));
      }

      // extract source and dest IPs
      //pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress();
      //pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress();

      // print source and dest IPs
      //printf("Source IP is '%s'; Dest IP is '%s'\n", srcIP.toString().c_str(), destIP.toString().c_str());

      pcapWriter.writePacket(rawPacket);
    }
  }
  // close the file
  reader.close();
  printf("done");
  return 0;
}
