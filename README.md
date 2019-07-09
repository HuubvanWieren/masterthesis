# My masterthesis

This repository contains all code used for my masterthesis. Research in progress...

## Setup
Ubuntu 18.04 LTS was used on all machines. Instructions are made for this OS.

### PcapPlusPlus
To be able to edit Pcap files with C++, which is significantly faster than Python.
Download, extract and install PcapPlusPlus from [here](https://github.com/seladb/PcapPlusPlus/releases/tag/v19.04). ('pcapplusplus-19.04-ubuntu-18.04-gcc-7.tar.gz')

libpcap-dev:
```bash
sudo apt-get install libpcap-dev
```

### IOVisor BCC
To be able to make and attach eBPF programs

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


### Netmap
Netmap can be used in combination with Tcpreplay in order to replay pcap files faster. Netmap uses kernel bypassing.
Download Netmap from [here](https://github.com/luigirizzo/netmap).

```bash
./configure
make
sudo make install
```

### TCPReplay
Instructions can be found [here](https://tcpreplay.appneta.com/wiki/installation.html).
