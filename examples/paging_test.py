#!/usr/bin/env python2.7
from autofocus import AFSample, AFClientError

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

i = 0
try:
    for sample in AFSample.search(query):

      i += 1
      #print sample.md5
except AFClientError as e:
  print e

print "%d samples" % (i,)