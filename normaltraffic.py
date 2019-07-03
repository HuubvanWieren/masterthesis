import json
import sys
import os
import json
import random
import Utils
import subprocess

def generatePcap(attackkey, overlap):
	#opening signature
	try:
		f = open("signatures/" + attackkey + ".json", 'r')
		fp = json.loads(f.read())
	except:
		print("Opening signature failed")
		return;
	
	#generate textfile with overlapping IPs
	ip_list = []
	for item in fp['src_ips']:
		ip_list.append(Utils.ip_to_uint32(item['ip']))
	resultList = random.sample(ip_list, round((len(ip_list)/100*overlap)))
	filename = str(overlap) + '.txt'
	with open(os.path.join('./normal_pcaps/',filename), 'w') as f:
		for ip in resultList:
			f.write('%s\n' % ip)

def generatePcaps(attackkey, overlap_set):
	for overlap in overlap_set:
		generatePcap("968117c31b16d683deae5f5ec641c88f", overlap)

if __name__ == '__main__':
	overlap_set = [77,83,85]
	generatePcaps("968117c31b16d683deae5f5ec641c88f", overlap_set)
	
	subprocess.call(["make","-C","normal_pcaps","-f","makefile","all"])
	
	
	for n in overlap_set:
		subprocess.call(["./generate",str(n)],cwd="normal_pcaps")
		subprocess.call(["rm", str(n)+".txt"],cwd="normal_pcaps")
		

	subprocess.call(["make","-C","normal_pcaps","-f","makefile","clean"])