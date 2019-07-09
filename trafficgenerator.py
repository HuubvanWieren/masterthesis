import normaltraffic
import attacktraffic
import subprocess
import shlex

def replayTraffic(device,overlap):
    tcpreplaystring = "sudo tcpreplay --topspeed --loop=1000 --limit 791615 --preload-pcap -i %s attack_pcaps/ddos.pcap" % device
    tcpreplaystring2 = "sudo tcpreplay --topspeed --loop=1000 --limit 791615 --preload-pcap -i %s normal_pcaps/normal%s.pcap" % (device,overlap)
    subprocess.Popen(shlex.split(tcpreplaystring))
    subprocess.Popen(shlex.split(tcpreplaystring2))


if __name__ == '__main__':
    overlap_set = [1, 50, 100]
    attacktraffic.generateDDoSPcap("a877a80fc3e21a6f001c4d2f514ed993")
    normaltraffic.generatePcaps("a877a80fc3e21a6f001c4d2f514ed993", overlap_set)

