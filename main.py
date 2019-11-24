from pexpect import pxssh
import pexpect
import subprocess
import shlex
import re
import time
import os
import csv
import operator
import json
from xdp_filters import IP_Filter, source_port_Filter, IP_proto_Filter, DNS_type_Filter

overlap_set = [0]
#attackkey = "a877a80fc3e21a6f001c4d2f514ed993"

path_to_json = 'signatures/'
json_files = [pos_json for pos_json in os.listdir(path_to_json) if pos_json.endswith('.json')]

udp_attacks = []
with open('test.csv', 'r') as f:
    reader = csv.reader(f)
    udp_attacks = list(reader)

filter = IP_Filter()

try:
    s=pxssh.pxssh()
    hostname = "10.0.0.41"
    username = "masterstudent"
    password = "raadme1212"
    s.login(hostname,username,password)
    s.sendline("cd masterthesis")
    s.prompt()
except pxssh.ExceptionPxssh:
    print("ssh connection failed")

#for jf in json_files:
#    attackkey = jf[:-5]
subprocess.call(shlex.split("make -C analysis -f makefile all"))
for fp in udp_attacks:
    attackkey = fp[0]
    
    filter.attackkey = attackkey
    
    s.sendline("python3 preparepcaps.py " + attackkey)
    s.prompt()
    print(s.before)
    
    start = time.time()
    filter.attach()
    end = time.time()
    print(end-start)
    for overlap in overlap_set:
        p1 = subprocess.Popen(shlex.split("sudo tcpdump -i enx503eaa208d37 -B 919400 -n -s 64 -K -w analysis/packetsreceived"+str(overlap)+".pcap"),preexec_fn=os.setpgrp)
        s.sendline("sudo python3 trafficgenerator.py " + str(overlap))
        time.sleep(1)
        s.prompt()
        print(s.before)
        pgid = os.getpgid(p1.pid)
        subprocess.check_call(["sudo", "kill", str(pgid)])
        #os.waitpid(p1.pid, 0)
        time.sleep(1)
    filter.remove()

    
    
    for overlap in overlap_set:
        #print("Attack a877a80fc3e21a6f001c4d2f514ed993 with overlap: " + str(overlap))
        subprocess.call(shlex.split("./analysis/countfntn analysis/packetsreceived"+str(overlap)+".pcap " + str(overlap) +" " + attackkey))
        #subprocess.call(shlex.split("rm analysis/packetsreceived"+str(overlap)+".pcap"))
    
    s.prompt()
    print(s.before)
    
subprocess.call(shlex.split("make -C analysis -f makefile clean"))    

s.logout()

