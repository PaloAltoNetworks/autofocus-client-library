#!/usr/bin/env python
from autofocus import AutoFocusAPI, AFSample
from pprint import pprint

i = 0
#    for sample in AFSample.search(field = "sample.tasks.http", value = "126.4.252.239", operator = "contains"):
for sample in AFSample.search(field = "sample.malware", value = "1", operator = "is"):
    i += 1
    pprint(sample.__dict__)
    pprint(sample.get_analyses())

print "%d results" % (i,)


#sample.analysis[0].time

# "field": "sample.sha256",
# "operator": "is",
# "value": "5dbae27c90a94f777e43314da78389537efbde883ff365e81daef568744370ed"
#samples = AFSample.search(field = "sample.md5", value = "2c1e4d3434cc5beffb3a2eccc9623496")

#print samples[0].sha256


# Demo pulling samples by md5 to get their sha256

sample_md5s = []

# Find 200 hashes:
i = 0
for sample in AFSample.search(field = "sample.malware", value = "1", operator = "is"):
    i += 1
    if i > 200:
        break
    sample_md5s.append(sample.md5)

AutoFocusAPI.search_operator = "any"

for I in (1, 2):
    search_terms = [{"field" : "sample.md5", "value" : v} for v in sample_md5s[(I*100)-100:I*100]]

    for sample in AFSample.search(*search_terms):
        print "%s -> %s" % (sample.md5, sample.sha256)

# Larg result sets
#AutoFocusAPI.page_size = 1000
#
#i = 0
#for sample in AFSample.search(field = "sample.malware", value = "1", operator = "is"):
#
#    i += 1
#    if i > 4050:
#        break
#
#print "%d results" % (i,)
