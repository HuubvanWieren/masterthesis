#!/bin/sh

attackkey=$1

cd attack_pcaps
make -f makefile all
./generate ${attackkey}.pcap
make  -f makefile clean
cd ..


#sudo tcpreplay --topspeed --loop=1000 --limit 791615 --preload-pcap -i ${device} attack_pcaps/ddos.pcap &
#sudo tcpreplay --topspeed --loop=1000 --limit 791615 --preload-pcap -i ${device} normal_pcaps/normal50.pcap


