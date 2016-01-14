from autofocus import AFSession, AutoFocusException, AutoFocusAPI

#AutoFocusAPI.api_key = "<my API key>"

######################################################
# Look for email session data for the Rodecap sample #
######################################################
query = """
{
    "operator":"all",
    "children":[
        {
            "field":"sample.tag_class",
            "operator":"is","value":
            "malware_family"
        },{
            "field":"session.emailsender",
            "operator":"has any value",
            "value":""
        },{
            "field":"sample.tag",
            "operator":"is in the list",
            "value":["Commodity.Rodecap"]
        }
    ]
}
"""

# session is an instance of AFSession
for session in AFSession.search(query):
    print "to:{} from:{} charset:{} subject:{}".format(
        session.email_recipient,
        session.email_sender,
        session.email_charset,
        # Sometimes there is unicode data in the responses, be sure to set utf-8 encoding when printing, see the charset attribute
        session.email_subject.encode("utf-8") if session.email_charset.lower() == "utf-8" else session.email_subject
    )