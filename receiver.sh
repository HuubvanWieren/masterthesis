sudo tcpdump -i wlp2s0 dst 10.0.0.50 -w analysis/packetsreceived.pcap


make -C analysis -f makefile all
./analysis/countfntn
