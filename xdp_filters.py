from bcc import BPF, table
import socket
import struct
import ctypes as ct
import Utils
import json
import os
# from ctypes import *
from datetime import datetime
import time
import ipaddress

class IP_Filter:
    
    EthernetDevice = "enx503eaa208d37"
    AttackKey = "a877a80fc3e21a6f001c4d2f514ed993"
    SrcFile = "eBPF_programs/ip-blacklist.c"
    
    def __init__(self, device=EthernetDevice, attackkey=AttackKey, srcfile=SrcFile):
        self.device = device
        self.attackkey = attackkey
        self.srcfile = srcfile
        self.__bpf = None
        
    def attach(self):
        ip_list = []
        ##################3
        #26d9d6efa0903fc32c5dcf3f543b450d
        #   try:
        #    f = open("signatures/26d9d6efa0903fc32c5dcf3f543b450d.json", 'r')
        #    fp = json.loads(f.read())
        #except:
        #    print("Opening signature failed")
        #for item in fp['src_ips']:
        #    if type(item) == dict:
        #        ip_list.append(Utils.ip_to_uint32(item['ip']))
        #    else: #type(item) == str:
        #        ip_list.append(Utils.ip_to_uint32(item))
        #print(len(ip_list))
        
        ####################
    
    
        try:
            f = open("signatures/" + self.attackkey + ".json", 'r')
            fp = json.loads(f.read())
        except:
            print("Opening signature failed")
        print(self.attackkey)
        for item in fp['src_ips']:
            if type(item) == dict:
                ip_list.append(Utils.ip_to_uint32(item['ip']))
            else: #type(item) == str:
                ip_list.append(Utils.ip_to_uint32(item))
        print(len(ip_list))

        #open eBPF c source code
        with open(self.srcfile, 'r') as f:
            file = ''.join(f.readlines())

        self.__bpf = BPF(self.srcfile)
        functions = self.__bpf.load_func('xdp_prog', BPF.XDP)
        print("eBPF progam loaded")
        self.__bpf.attach_xdp(self.device, functions, 0)
        print("eBPF program attached")

        #load blacklist map
        blacklist = self.__bpf["iplist"]
        blacklist.clear()

        #put the to block ip addreses in map
        for item in ip_list:
            blacklist[ct.c_uint32(item)] = ct.c_uint32(1)
        
        #size = 0
        #filename = 'test.txt'
        #with open(os.path.join(filename), 'w') as f:
        #    for k,v in blacklist.items():
        #        size += 1
        #        f.write('%s\n' % Utils.uint32_to_ip(k.value))
        #print("Number of IP addresses being blocked: " + str(size))
        print("attached")
    def remove(self):
        self.__bpf.remove_xdp(self.device, 0)
        print("remove")


class IP_proto_Filter:

    EthernetDevice = "enx503eaa208d37"
    AttackKey = "a877a80fc3e21a6f001c4d2f514ed993"
    SrcFile = "eBPF_programs/ip-proto-filter.c"
    
    def __init__(self, device=EthernetDevice, attackkey=AttackKey, srcfile=SrcFile):
        self.device = device
        self.attackkey = attackkey
        self.srcfile = srcfile
        self.__bpf = None
    
    def attach(self):
        print(self.attackkey)
        try:
            f = open("signatures/" + self.attackkey + ".json", 'r')
            fp = json.loads(f.read())
        except:
            print("Opening signature" + self.attackkey + "failed")

        ip_list = []
         
        for item in fp['src_ips']:
            if type(item) == dict:
                ip_list.append(Utils.ip_to_uint32(item['ip']))
            else: #type(item) == str:
                ip_list.append(Utils.ip_to_uint32(item))

        srcports_list = []
        for item in fp['src_ports']:
            srcports_list.append(int(item))
    
        dstports_list = []
        for item in fp['dst_ports']:
            dstports_list.append(int(item))
        
        protocol_list = []
        if fp['protocol'] == 'UDP':
            print("match udp")
            protocol_list.append(17)
        elif  fp['protocol'] == 'TCP':
            print("match tcp")
            protocol_list.append(6)
        else:
            protocol_list.append(17)    
        
        #open eBPF c source code
        with open(self.srcfile, 'r') as f:
            file = ''.join(f.readlines())

        self.__bpf = BPF(text=file)
        functions = self.__bpf.load_func('xdp_prog', BPF.XDP)
        print("eBPF progam loaded")
        self.__bpf.attach_xdp(self.device, functions, 0)
        print("eBPF program attached")

        #load blacklist map
        blacklist = self.__bpf["iplist"]
        blacklist.clear()

        proto_blacklist = self.__bpf["l4proto"]
        proto_blacklist.clear()
        
        src_ports = self.__bpf["srcports"]
        src_ports.clear()

        dst_ports = self.__bpf["dstports"]
        dst_ports.clear()

        for item in protocol_list:
            proto_blacklist[ct.c_uint32(item)] = ct.c_uint32(0)
        
        for item in srcports_list:
            src_ports[ct.c_uint16(item)] = ct.c_uint32(0)
    
        for item in dstports_list:
            dst_ports[ct.c_uint16(item)] = ct.c_uint32(0)
        
        #put the to block ip addreses in map
        for item in ip_list:
            blacklist[ct.c_uint32(item)] = ct.c_uint32(0)
            
        size = 0
        filename = 'test.txt'
        with open(os.path.join(filename), 'w') as f:
            for k,v in dst_ports.items():
                    size += 1
                    f.write('%s\n' % k.value)
        #f.write('%s\n' % Utils.uint32_to_ip(k.value))
        print("Number of dstports addresses being blocked: " + str(size))

                
    def remove(self):  
        #self.__bpf.trace_print()    
        self.__bpf.remove_xdp(self.device, 0)
        print('done')

class source_port_Filter:

    EthernetDevice = "enx503eaa208d37"
    AttackKey = "a877a80fc3e21a6f001c4d2f514ed993"
    SrcFile = "eBPF_programs/source-port-filter.c"
    
    def __init__(self, device=EthernetDevice, attackkey=AttackKey, srcfile=SrcFile):
        self.device = device
        self.attackkey = attackkey
        self.srcfile = srcfile
        self.__bpf = None
    
    def attach(self):
        
        print(self.attackkey)
        try:
            f = open("signatures/" + self.attackkey + ".json", 'r')
            fp = json.loads(f.read())
        except:
            print("Opening signature" + self.attackkey + "failed")

        srcports_list = []
        for item in fp['src_ports']:
            srcports_list.append(int(item))
        
        #open eBPF c source code
        with open(self.srcfile, 'r') as f:
            file = ''.join(f.readlines())
        s = time.time()
        self.__bpf = BPF(text=file)
        functions = self.__bpf.load_func('xdp_prog', BPF.XDP)
        print("eBPF progam loaded")
        self.__bpf.attach_xdp(self.device, functions, 0)
        print("eBPF program attached")
        
        src_ports = self.__bpf["srcports"]
        src_ports.clear()

        for item in srcports_list:
            src_ports[ct.c_uint16(item)] = ct.c_uint32(0)

        en = time.time()
        print(en-s)
    def remove(self):  
        #self.__bpf.trace_print()    
        self.__bpf.remove_xdp(self.device, 0)
        print('done')
    
    
class UDP_Filter:
    
    EthernetDevice = "enx503eaa208d37"
    AttackKey = "2ed22f7c537425a39329988d6979810f"
    SrcFile = "eBPF_programs/udp-filter.c"
    
    def __init__(self, device=EthernetDevice, attackkey=AttackKey, srcfile=SrcFile):
        self.device = device
        self.attackkey = attackkey
        self.srcfile = srcfile
        self.__bpf = None
    
    def attach(self):
        print(self.attackkey)
         

        ip_list = []
         
        f = open("signatures/26d9d6efa0903fc32c5dcf3f543b450d.json", 'r')
        fp = json.loads(f.read())
        for item in fp['src_ips']:
            if type(item) == dict:
                ip_list.append(Utils.ip_to_uint32(item['ip']))
            else: #type(item) == str:
                ip_list.append(Utils.ip_to_uint32(item))
        
        print("ip addresses: ", len(ip_list))
        try:
            f = open("signatures/" + self.attackkey + ".json", 'r')
            fp = json.loads(f.read())
        except:
            print("Opening signature" + self.attackkey + "failed")


        srcports_list = []
        for item in fp['src_ports']:
            srcports_list.append(int(item))
    
        dstports_list = []
        for item in fp['dst_ports']:
            dstports_list.append(int(item))
        
        protocol_list = []
        if fp['protocol'] == 'UDP':
            print("match udp")
            protocol_list.append(17)
        elif  fp['protocol'] == 'TCP':
            print("match tcp")
            protocol_list.append(6)
        else:
            protocol_list.append(17)    
        
        #open eBPF c source code
        with open(self.srcfile, 'r') as f:
            file = ''.join(f.readlines())

        self.__bpf = BPF(text=file)
        functions = self.__bpf.load_func('xdp_prog', BPF.XDP)
        print("eBPF progam loaded")
        self.__bpf.attach_xdp(self.device, functions, 0)
        print("eBPF program attached")

        #load blacklist map
        blacklist = self.__bpf["iplist"]
        blacklist.clear()

        proto_blacklist = self.__bpf["l4proto"]
        proto_blacklist.clear()
        
        src_ports = self.__bpf["srcports"]
        src_ports.clear()

        dst_ports = self.__bpf["dstports"]
        dst_ports.clear()

        for item in protocol_list:
            proto_blacklist[ct.c_uint32(item)] = ct.c_uint32(0)
        
        for item in srcports_list:
            src_ports[ct.c_uint16(item)] = ct.c_uint32(0)
    
        for item in dstports_list:
            dst_ports[ct.c_uint16(item)] = ct.c_uint32(0)
        
        #put the to block ip addreses in map
        for item in ip_list:
            blacklist[ct.c_uint32(item)] = ct.c_uint32(0)
            
        print("Filter attached")

                
    def remove(self):  
        #self.__bpf.trace_print()    
        self.__bpf.remove_xdp(self.device, 0)
        print('done')
    
    
class DNS_type_Filter:
    EthernetDevice = "enx503eaa208d37"
    AttackKey = "a877a80fc3e21a6f001c4d2f514ed993"
    SrcFile = "eBPF_programs/dns-type-filter.c"
    
    def __init__(self, device=EthernetDevice, attackkey=AttackKey, srcfile=SrcFile):
        self.device = device
        self.attackkey = attackkey
        self.srcfile = srcfile
        self.__bpf = None
    
    def attach(self):
        #open eBPF c source code
        with open(self.srcfile, 'r') as f:
            file = ''.join(f.readlines())
        s = time.time()
        self.__bpf = BPF(text=file)
        functions = self.__bpf.load_func('xdp_prog', BPF.XDP)
        print("eBPF progam loaded")
        self.__bpf.attach_xdp(self.device, functions, 0)
        print("eBPF program attached")
        
        en = time.time()
        print(en-s)
    def remove(self):  
        self.__bpf.trace_print()    
        self.__bpf.remove_xdp(self.device, 0)
        print('done')
    
