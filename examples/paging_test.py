#!/usr/bin/env python2.7
from autofocus import AFSample

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
for sample in AFSample.search(query):

  i += 1
  #print sample.md5

print "%d samples" % (i,)