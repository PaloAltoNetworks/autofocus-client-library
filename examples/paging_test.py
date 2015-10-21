#!/usr/bin/env python2.7
from autofocus import AFSample, AFClientError, AutoFocusAPI

query = """
{
    "operator": "all",
    "children": [
    {
        "field": "sample.malware",
        "operator": "is",
        "value": "0"
    },
    {
        "field": "sample.tag_scope",
        "operator": "is",
        "value": "unit42"
    }
  ]
}
"""
AutoFocusAPI.page_size = 3000
samples = []
print "sha256,md5,filetype,size"
try:
    for sample in AFSample.search(query):
        samples.append(sample)
        #print ",".join((sample.sha256,sample.md5, sample.filetype, str(sample.size)))
        #print sample.md5
except AFClientError as e:
    print e

print "%d samples" % (len(samples),)

