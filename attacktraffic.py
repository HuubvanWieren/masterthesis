import subprocess
import shlex

def generateDDoSPcap(attackkey):
    try:
        command = "./gen-ddos-pcap.sh %s" % (attackkey)
        print(shlex.split(command))
        subprocess.call(shlex.split(command))
    except:
        print("DDoS Pcap rewrite went wrong")
        return

