from autofocus import AFTag
from autofocus import AFTagAbsent
from autofocus import AFTagGroup
from autofocus import AFTagGroupAbsent

## Documentation around valid tag queries can be found in "tag identifiers" at:
# https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_api/perform-direct-searches/get-tags



# Search for a tag, finds all tags with 4h in the name
tags = AFTag.search([{"field":"tag_name","operator":"contains","value":"4h"}])



# Identify groups a tag may be a part of
try:
    tag = AFTag.get("Commodity.Genieo")

    # We've pulled a tag, now loop through it's groups
    for tag_group in tag.groups:

        # What other tags are in this tag_gropu?
        for tag in tag_group.tags:

            print("{} is in tag group {}".format(tag.public_name, tag_group.name))

        break # We're only curious about the first tag group

except AFTagAbsent:
    pass # Tag didn't exist in Autofocus



# Search for a tags in a particular group
try:
    tag_group = AFTagGroup.get("OSX")

    print("{} - {}".format(tag_group.name, tag_group.description))

    for tag in tag_group:

        print("{} is in groups:".format(tag.public_name))

        for group in tag.groups: # AFTag.groups is a list of groups the tag belongs to
            print("- {}".format(group.name))

except AFTagGroupAbsent:
    pass # Tag group doesn't exist



# List tags
# Tags will be a list of all tags that are visible to your API Key (your user)
# #Default scope here is visible
tags = AFTag.list()
