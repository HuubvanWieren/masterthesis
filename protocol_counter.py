import os
import json
import operator

path_to_json = 'fingerprints/'
json_files = [pos_json for pos_json in os.listdir(path_to_json) if pos_json.endswith('.json')]

protocols={}

for jf in json_files:
	with open('fingerprints/' + jf) as f:
		data=json.load(f)
	protocol = data.get("protocol")

	if protocol not in protocols:
		protocols[protocol]=0
	protocols[protocol] += 1

print(sorted(protocols.items(),key=lambda kv: kv[1]))

