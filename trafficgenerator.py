import preparepcaps
import subprocess
import shlex
import os
import time

#a877a80fc3e21a6f001c4d2f514ed993

attackkey = "a877a80fc3e21a6f001c4d2f514ed993" # "955a5cd15843aa5c4155fd3f69651e15"  # "955a5cd15843aa5c4155fd3f69651e15"
#--loop 1000 --limit 791615
def replayTraffic(device,overlap):
    tcpreplaystring = "sudo tcpreplay --loop 1000 --limit 1582358 -p 150000 --preload-pcap -i %s attack_pcaps/ddos.pcap" % device
    tcpreplaystring2 = "sudo tcpreplay --loop 1000 --limit 1582358 -p 150000 --preload-pcap -i %s normal_pcaps/normal%s.pcap" % (device,overlap)
    p1 = subprocess.Popen(shlex.split(tcpreplaystring))
    p2 = subprocess.Popen(shlex.split(tcpreplaystring2))

    while ((p1.poll() is None) or (p2.poll() is None)):
        time.sleep(5)
    p1.kill()
    p2.kill()

if __name__ == '__main__':
    overlap_set = [0, 76, 100]
    preparepcaps.generateAllPcaps(attackkey, overlap_set)
    replayTraffic("enp0s31f6", 100)
