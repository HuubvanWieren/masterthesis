# My masterthesis

This repository contains all code used for my masterthesis. Research in progress...

## Setup
Ubuntu 18.04 LTS was used on all machines. Instructions are made for this OS.

# Install to edit Pcap files with C++
Download, extract and install PcapPlusPlus from [here](https://github.com/seladb/PcapPlusPlus/releases/tag/v19.04). ('pcapplusplus-19.04-ubuntu-18.04-gcc-7.tar.gz')

libpcap-dev:
```bash
sudo apt-get install libpcap-dev
```

# Install to to make and attach eBPF programs
BCC:
```bash
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)
```

python bcc binding package:
```
sudo apt-get install python3-bcc
```



