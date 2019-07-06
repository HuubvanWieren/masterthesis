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

device = "ens33"
src_file = 'test4.c'

try:
    f = open("signatures/" + "19655b0e20c74dcffa056a78cde7ee0f" + ".json", 'r')
    fp = json.loads(f.read())
except:
    print("Opening signature failed")

size = 0
# generate textfile
ip_list = []
for item in fp['src_ips']:
    size += 1
    ip_list.append(Utils.ip_to_uint32(item['ip']))
print(size)
#open eBPF c source code
with open(src_file, 'r') as f:
    file = ''.join(f.readlines())

b = BPF(text=file)
functions = b.load_func('xdp_prog', BPF.XDP)
print("loaded")
b.attach_xdp(device, functions, 0)
print("attached")

value = 0
list = []

# list = b["packeth"]
blacklist = b["iplist"]
blacklist.clear()

size2 = 0
for item in ip_list:
    blacklist[ct.c_uint32(item)] = ct.c_uint32(1)
    size2 += 1

print(size2)

size3 = 0
filename = 'test.txt'
with open(os.path.join(filename), 'w') as f:
    for k,v in blacklist.items():
        size3 += 1
        f.write('%s\n' % Utils.uint32_to_ip(k.value))
print(size3)

# table.PerCpuHash.__setitem__(blacklist,4,3)
# blacklist.#__setitem__(3,2)
# blacklist[a] = a
# blacklist[ct.c_uint(ip_to_uint32("0.0.0.0"))] = 3
# blacklist.update({ip_to_uint32("0.0.0.0"):1})

# flow = []
# print("Running!")
# while True:
#     try:
#         for k, v in list.items():
#             if v[0].cntr > value:
#                 print(value)
#                 flow.append([value, v[0].cntr, v[0].IPsrc, v[0].IPdst, v[0].proto, v[0].srcPort, v[0].dstPort, v[0].totl])#, v[0].totl, v[0].ttl])
#                 value += 1
#     except KeyboardInterrupt:
#         print("Removing filter from device")
#         break

while True:
    try:
        # for k, v in blacklist.items():
        #     if v[0] > 1:
        value += 1
                # print(k.value, " ", Utils.uint32_to_ip(k.value), ' ', v[0])
                # flow.append([value, v[0].cntr, v[0].IPsrc, v[0].IPdst, v[0].proto, v[0].srcPort, v[0].dstPort, v[0].totl])#, v[0].totl, v[0].ttl])
                # value += 1
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

# try:
#     for k,v in blacklist.items():
#         if v[0] > 1:
#             print(k.value, " ", Utils.uint32_to_ip(k.value), ' ', v[0])
# except:
#     print("error")

b.remove_xdp(device, 0)
# b.trace_print()

# table = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}
# for i in flow:
#     print(i[0], i[1], Utils.uint32_to_ip(i[2]), Utils.uint32_to_ip(i[3]), i[4],socket.ntohs(i[5]),socket.ntohs(i[6]),socket.ntohs(i[7]))
#     print(type(Utils.uint32_to_ip(i[2])))
#     print(type(i[2]))

print('done')