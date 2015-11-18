from autofocus import AFSession, AFException, AutoFocusAPI

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

for session in AFSession.search(query):
    print "to:{} from:{} subject:{}".format(session.email_recipient, session.email_sender, session.email_subject)