#!/usr/bin/env python3

import sys
import os
import json
import random
import time
import socket
import struct
import subprocess


def uint32_to_ip(ipn):
    t = struct.pack('I', ipn)
    return socket.inet_ntoa(t)


def ip_to_uint32(ip):
    t = socket.inet_aton(ip)
    return struct.unpack('I', t)[0]


def generateTxts(fp, overlap):
    # First empty the folder
    # filelist = [f for f in os.listdir('./txt/')]
    # for f in filelist:
    #     os.remove(os.path.join('./txt/',f))

    ip_list = []
    for item in fp['src_ips']:
        ip_list.append(ip_to_uint32(item['ip']))
    resultList = random.sample(ip_list, round((len(ip_list)/100*overlap)))
    filename = str(overlap) + '.txt'
    with open(os.path.join('./data/',filename), 'w') as f:
        for ip in resultList:
            f.write('%s\n' % ip)


if __name__ == '__main__':
    start = time.time()
    overlap_set = [10,20,30,40,50,60,70,80,90,100]

    # Load fingerprint from argv
    if len(sys.argv) == 2:
        f = open(sys.argv[1], 'r')
        fingerprint = json.loads(f.read())
    else:
        raise ValueError('No fingerprint file supplied.')
    
    # This line extracts the ID from the fingerprint file (might use later)
    filename = os.path.splitext(os.path.basename(sys.argv[1]))[0] 
    
    for overlap in overlap_set:
        generateTxts(fingerprint, overlap)
    
    subprocess.call(["make","-f","makefile","all"])
    subprocess.call(["./randomize","40"])
	
    end = time.time()
    print('This took me', end-start, 'seconds.')
	
	