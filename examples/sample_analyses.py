from autofocus import AFSample, AFConnectionActivity, AFUserAgentFragment, AFRelatedMacro

#AutoFocusAPI.api_key = "<my API key>"

sample = AFSample.get("8404e06ff383275462298e830bebe9540fab2092eca5523649d74e6e596ac23d")

for analysis in sample.get_analyses(AFConnectionActivity):
    analysis

# user agent fragments
sample = AFSample.get("66ee855c9ea5dbad47c7da966dbdb7fef630c0421984f7eeb238f26fb45493f2")

# Can pull the user agent analyses in many different ways.
for analysis in sample.get_analyses(AFUserAgentFragment):
    print analysis

for analysis in sample.get_analyses('user_agent'):
    print analysis

for analysis in sample.get_analyses([AFUserAgentFragment]):
    print analysis

for analysis in sample.get_analyses(['user_agent']):
    print analysis

# service activity
sample = AFSample.get("652c70c144f0d2d177695c5dc47ed9fcc1606ebdf78a636cace91988f12185fa")

for analysis in sample.get_analyses(['service']):
    print analysis

# process activity
sample = AFSample.get("09dd98c93cde02935f885a72a9789973e1e17b8a1d2b8e3bd34d5fc27db46fde")

for analysis in sample.get_analyses(['registry']):
    print analysis

# process activity
sample = AFSample.get("09dd98c93cde02935f885a72a9789973e1e17b8a1d2b8e3bd34d5fc27db46fde")

for analysis in sample.get_analyses(['process']):
    print analysis

# Miscellaneous
sample = AFSample.get("09dd98c93cde02935f885a72a9789973e1e17b8a1d2b8e3bd34d5fc27db46fde")

for analysis in sample.get_analyses(['misc']):
    print analysis

# Mutex Analysis
for sample in AFSample.search({ "field" : "sample.tasks.mutex", "operator" : "has any value", "value" : ""}):
    for analysis in sample.get_analyses(['mutex']):
        print analysis.function_name
    break

# Java API  Analysis
sample = AFSample.get("2b69dcee474f802bab494983d1329d2dc3f7d7bb4c9f16836efc794284276c8e")

for analysis in sample.get_analyses(['japi']):
    print type(analysis)

# HTTP Analysis
sample = AFSample.get("c1dc94d92c0ea361636d2f08b63059848ec1fb971678bfc34bcb4a960a120f7e")

for analysis in sample.get_analyses(['http']):
    print type(analysis)

# DNS Analysis
sample = AFSample.get("21e5053f89c89c6f71e8028f20139f943f75f8d78210404501d79bae85ac6500")

for analysis in sample.get_analyses(['dns']):
    print type(analysis)

 #Behavior analysis
sample = AFSample.get("438ea5ec331b15cb5bd5bb57b760195734141623d83a03ffd5c6ec7f13ddada9")

for analysis in sample.get_analyses(['behavior_type']):
    print type(analysis)

# Retrieve Macro Hash
for analysis in AFSample.get_analyses_by_hash("bf2f1c68a5e043a1ed83603a0768c3ec9bd49706c5124c692f43db0e35fc0b54", AFRelatedMacro):
    print analysis

#Connection testing hashes
test_hashes = (
    "7a1f5a5fe0a3bd5031da504d67e224f35b96fd1fd9771f67bc0936999d4d292b", # Has udp
    "90c6cef834a7528e6771959c2e093c230866167eb8d1f16362a5128c0c35694f", # Has tcp-connection, udp-connection
    "0bb615a781035e4d0143582ea5a0a4c9486625585de1cd8e3a8669cd2a1b29f3"  # Has tcp-listen
)

# Get a sample by hash
for sample_hash in test_hashes:

    sample = AFSample.get(sample_hash)

    for analysis in sample.get_analyses(['connection']):
        print type(analysis)

#        for tag in sample.tags:
#            print tag.public_name

query = """
{
    "operator":"all",
    "children":[
        {"field":"sample.tasks.connection","operator":"contains","value":"tcp"},
        {"field":"sample.tag_scope","operator":"is","value":"unit42"}
    ]
}
"""

# sample is instance of AFSample
for sample in AFSample.search(query):

    # analysis is a subclass of AFAnalysis
    for analysis in sample.get_analyses(['connection']):
        print type(analysis)

    break
