#!/usr/bin/env python
from autofocus import AFTag, AFSample, AutoFocusAPI
from pprint import pprint
import sys

unit42_tags = []

# Pull all unit 42 tags and add them to the search terms
for tag in AFTag.list(scope = "Unit42", pageSize = 200):

    if tag.tag_definition_scope_id != 4:
        continue
    
    unit42_tags.append(tag)

i = 0
pg = 100
while i <= len(unit42_tags):

    search_terms = [
        { "field" : "sample.malware", "operator" : "is", "value" : "0"},
    ]
    search_terms.append(
        { 
            "field" : "sample.tag", 
            "operator" : "is in the list", 
            "value" : [v.public_tag_name for v in unit42_tags[i:pg]] 
        }
    )

    for sample in AFSample.search(*search_terms):
        print "{} -> {}".format(sample.sha256, ",".join(sample.tag))
    
    i += pg
