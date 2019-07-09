import normaltraffic
import attacktraffic
import subprocess
import shlex
import os
import time

def replayTraffic(device,overlap):
    tcpreplaystring = "sudo tcpreplay -p 10000 --loop=1000 --limit 791615 --preload-pcap -i %s attack_pcaps/ddos.pcap" % device
    tcpreplaystring2 = "sudo tcpreplay -p 10000 --loop=1000 --limit 791615 --preload-pcap -i %s normal_pcaps/normal%s.pcap" % (device,overlap)
    p1 = subprocess.Popen(shlex.split(tcpreplaystring))
    p2 = subprocess.Popen(shlex.split(tcpreplaystring2))

    while ((p1.poll() is None) or (p2.poll() is None)):
        time.sleep(5)
    p1.kill()
    p2.kill()
if __name__ == '__main__':
    overlap_set = [1, 50, 100]
    #attacktraffic.generateDDoSPcap("a877a80fc3e21a6f001c4d2f514ed993")
    #normaltraffic.generatePcaps("a877a80fc3e21a6f001c4d2f514ed993", overlap_set)
    replayTraffic("ens33", 50)	
