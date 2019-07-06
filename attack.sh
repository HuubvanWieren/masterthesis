#!/bin/sh

device=ens33


echo "start"
#sudo tcpreplay --loop 1000 --preload-pcap --mbps 10000 -i ${device} ddos2.pcap
sudo tcpreplay --loop 1000 --preload-pcap -i ${device} ddos2.pcap


