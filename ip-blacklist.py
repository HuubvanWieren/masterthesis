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
import time
import ipaddress

device = "enx503eaa208d37"
src_file = 'eBPF_programs/ip-blacklist.c'

try:
    f = open("signatures/" + "a877a80fc3e21a6f001c4d2f514ed993" + ".json", 'r')
    fp = json.loads(f.read())
except:
    print("Opening signature failed")

ip_list = []
for item in fp['src_ips']:
    ip_list.append(Utils.ip_to_uint32(item['ip']))

#open eBPF c source code
with open(src_file, 'r') as f:
    file = ''.join(f.readlines())

b = BPF(text=file)
functions = b.load_func('xdp_prog', BPF.XDP)
print("eBPF progam loaded")
b.attach_xdp(device, functions, 0)
print("eBPF program attached")

#load blacklist map
blacklist = b["iplist"]
blacklist.clear()

#put the to block ip addreses in map
for item in ip_list:
    blacklist[ct.c_uint32(item)] = ct.c_uint32(1)

size = 0
filename = 'test.txt'
with open(os.path.join(filename), 'w') as f:
    for k,v in blacklist.items():
        size += 1
        f.write('%s\n' % Utils.uint32_to_ip(k.value))
print("Number of IP addresses being blocked: " + str(size))

while True:
    try:
        time.sleep(5)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)
print('done')
