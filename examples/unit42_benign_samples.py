#!/usr/bin/env python
from autofocus import AFTag, AFSample, AutoFocusAPI
from pprint import pprint
from time import time
import sys

unit42_tags = {}

# Pull all unit 42 tags and add them to the search terms
for tag in AFTag.list(scope = "Unit42"):

#    if tag.tag_definition_scope_id != 4:
#        continue

    unit42_tags[tag.public_name] = tag

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
        },
        {
            "field": "sample.tag_class",
            "operator": "is not",
            "value": "campaign"
        }
    ]
}
"""

file_types = []
sample_metrics = {}

for sample in AFSample.search(query):

    for tag in sample.tags:

        # Skiping private tags
        if tag.definition_scope == "private":
            continue

        if tag.public_name not in unit42_tags:
            if "nit42" not in tag.public_name:
                sys.stderr.write("Hmm, not a known unit42 tag - %s\n" % (tag.public_name,))
            else:
                sys.stderr.write("Hmm, a unit42 tag missing int he unit42 scope query - %s\n" % (tag.public_name,))

        if tag.public_name not in sample_metrics:
            sample_metrics[tag.public_name] = { 'file_types' : {} }

        if sample.file_type not in file_types:
            file_types.append(sample.file_type)

        if sample.file_type not in sample_metrics[tag.public_name]['file_types']:
            sample_metrics[tag.public_name]['file_types'][sample.file_type] = 0

        sample_metrics[tag.public_name]['file_types'][sample.file_type] += 1

        if not "oldest_sample" in sample_metrics[tag.public_name] \
            or sample_metrics[tag.public_name]['oldest_sample'] > sample.create_date:
                sample_metrics[tag.public_name]['oldest_sample'] = sample.create_date

        if not "newest_sample" in sample_metrics[tag.public_name] \
                or sample_metrics[tag.public_name]['newest_sample'] < sample.create_date:
            sample_metrics[tag.public_name]['newest_sample'] = sample.create_date

# Looking for a report of
# Tag, <..., list of file type counts>, <oldest sample>, <newest sample>

o_file = open("/tmp/malicious_tags_benign_samples.%d.csv" % (time()), "w")

o_file.write("tag,")
for file_type in file_types:
    o_file.write(file_type + ",")
o_file.write("oldest_sample,newest_sample" + "\n")

for tag_name, metrics in sample_metrics.items():

    o_file.write(tag_name + ",")

    for file_type in file_types:
        if file_type in metrics['file_types']:
            o_file.write(str(metrics['file_types'][file_type]) + ",")
        else:
            o_file.write("0" + ",")

    o_file.write(str(metrics['oldest_sample']) + ",")
    o_file.write(str(metrics['newest_sample']) + "\n")

o_file.close()

