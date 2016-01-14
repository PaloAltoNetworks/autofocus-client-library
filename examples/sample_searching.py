from autofocus import AFSample, AFSampleAbsent

#AutoFocusAPI.api_key = "<my API key>"

###############################
# Searching for a single hash #
###############################
hash = "7f38fd3e55a4139d788a4475ab0a5d83bf7686a37ef5e54a65364a0d781b523c"
try:

    # sample is instance of AFSample()
    sample = AFSample.get(hash)

    # Using instrospection, you can analyze the attributes of the AFSample instance
    print "Pulled sample {} and got the follow attributes".format(hash)
    for k,v in sample.__dict__.items():
        print "\t{}={}".format(k, v)

except AFSampleAbsent:
    pass # The sample isn't in AutoFocus


################################################
# Run an autofocus query (Exported via the UI) #
################################################
query = '{"operator":"all","children":[{"field":"sample.malware","operator":"is","value":1}]}'

# * AFSample.search is a generator, so you have to iterate over the results, which is required since it's common
#   to search for large datasets
# * The client library handles all paging for you, so you just need to pose a question
#   and parse the results
for sample in AFSample.search(query):
    # sample is an instance of AFSample
    print sample.sha256
    break

#################################
# Searching for multiple hashes #
#################################

# Get a list of hashes you're interested in looking for
# IMPORTANT: The API currently has a 100 hash limit per query. You'll have to chunk hashes
# if you want to run more than 100 hashes.
hashes = [
    "7f38fd3e55a4139d788a4475ab0a5d83bf7686a37ef5e54a65364a0d781b523c",
    "9906a8a55e5a50d2993408c7f1ba9cf97d8f38ca3fe68750bb62a8d0785b8c4b",
    "b25a964c954d386ab67df52d20dbf210e803f0ada2ed6feb38fc5dc93e31c873",
    "47633cc3e4adf583c4b40e0f64b56eaf8005b4232e5bd493f811875e4c4d47a0"
]

# Build the query for AutoFocus API
search_terms = {
    "field" : "sample.sha256",
    "operator" : "is in the list",
    "value" : hashes
}

# Loop through the resulting samples
for sample in AFSample.search(search_terms):

    # Do cool things with sample
    print "{} is of file type {} and is {} bytes large".format(sample.sha256, sample.file_type, sample.size)
