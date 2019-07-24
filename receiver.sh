sudo tcpdump -i enx503eaa208d37 dst 10.0.0.50 -w analysis/packetsreceived.pcap


make -C analysis -f makefile all
./analysis/countfntn
