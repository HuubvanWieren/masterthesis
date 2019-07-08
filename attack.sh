#!/bin/sh

device=ens33


echo "start"
sudo tcpreplay --topspeed --loop=1000 --limit 791615 --preload-pcap -i ${device} attack_pcaps/ddos.pcap &
sudo tcpreplay --topspeed --loop=1000 --limit 791615 --preload-pcap -i ${device} normal_pcaps/normal50.pcap


