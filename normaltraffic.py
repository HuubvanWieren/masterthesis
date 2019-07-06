import json
import sys
import os
import json
import random
import Utils
import subprocess

def generateTxt(attackkey, overlap):
	#opening signature
	try:
		f = open("signatures/" + attackkey + ".json", 'r')
		fp = json.loads(f.read())
	except:
		print("Opening signature failed")
		return;
	
	#generate textfile
	ip_list = []
	for item in fp['src_ips']:
		ip_list.append(Utils.ip_to_uint32(item['ip']))
	resultList = random.sample(ip_list, round((len(ip_list)/100*overlap)))
	filename = str(overlap) + '.txt'
	with open(os.path.join('./normal_pcaps/',filename), 'w') as f:
		for ip in resultList:
			f.write('%s\n' % ip)

def generatePcaps(attackkey, overlap_set):
	subprocess.call(["make","-C","normal_pcaps","-f","makefile","all"])
	for overlap in overlap_set:
		generateTxt(attackkey, overlap)
	
	for n in overlap_set:
		subprocess.call(["./generate",str(n)],cwd="normal_pcaps") #call c++ program that generates pcap
		subprocess.call(["rm", str(n)+".txt"],cwd="normal_pcaps") #remove the txt file
	
	subprocess.call(["make","-C","normal_pcaps","-f","makefile","clean"])
if __name__ == '__main__':
	overlap_set = [1,50,100]
	generatePcaps("a877a80fc3e21a6f001c4d2f514ed993", overlap_set)
	
	
	
	

		

	