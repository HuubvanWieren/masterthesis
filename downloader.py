import os
import json
import ddosdb

path_to_json = 'signatures/'
json_files = [pos_json for pos_json in os.listdir(path_to_json) if pos_json.endswith('.json')]


protocols={}

for jf in json_files:
	with open('signatures/' + jf) as f:
		data=json.load(f)
	protocol = data.get("protocol")
	if protocol == 'HTTP':
		print(jf[:-5])
        	ddosdb.download_pcap("email","password",jf[:-5],True)

	if protocol not in protocols:
		protocols[protocol]=0
	protocols[protocol] += 1
