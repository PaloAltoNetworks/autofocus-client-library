from autofocus import AFSample

#AutoFocusAPI.api_key = "<my API key>"

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
