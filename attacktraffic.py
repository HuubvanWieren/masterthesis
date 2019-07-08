import subprocess
import shlex

def generateDDoSPcap(destIP, attackkey):
    try:
        subprocess.call(["make", "-C", "attack_pcaps", "-f", "makefile", "all"])
        subprocess.call(["./generate", attackkey+".pcap"], cwd="attack_pcaps")
        rewritestring = "tcprewrite --dstipmap=0.0.0.0/0:%s --infile=attack_pcaps/temp.pcap --outfile=attack_pcaps/ddos.pcap" % (destIP)
        subprocess.Popen(shlex.split(rewritestring))
        subprocess.call(["make", "-C", "attack_pcaps", "-f", "makefile", "clean"])
        subprocess.call(["rm", "attack_pcaps/temp.pcap"])
    except:
        print("DDoS Pcap rewrite went wrong")
        return


def replayTraffic(device,overlap):
    tcpreplaystring = "sudo tcpreplay --topspeed --loop=1000 --limit 791615 --preload-pcap -i %s attack_pcaps/ddos.pcap &" % device
    tcpreplaystring2 = "sudo tcpreplay --topspeed --loop=1000 --limit 791615 --preload-pcap -i %s normal_pcaps/normal%s.pcap" % (device,overlap)
    subprocess.Popen(shlex.split(tcpreplaystring))


if __name__ == '__main__':
    generateDDoSPcap("10.10.10.41","19655b0e20c74dcffa056a78cde7ee0f")
    replayTraffic("ens33", 50)
