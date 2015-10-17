#!/usr/bin/env python
import requests, json, sys, time, re
from pprint import pprint
from datetime import datetime
import autofocus_config

AF_APIKEY = autofocus_config.AF_APIKEY

# Useful information:
#
# * We're not doing any input validation in the client itself. We pass
#   the data to the API, and rely on 4XX errors to communicate invalid
#   requests. At the time this was written, the API DOES NOT validate search
#   values. So you can offer invalid IPs, such as 592.99.1.1 and it will
#   not balk. The result set will be empty, naturally.

_base_url = "https://autofocus.paloaltonetworks.com/api/v0.9"
_headers = {"Content-Type" : "application/json"}

class NotLoaded(object):
    pass

class AFClientError(Exception):
    """
    Notes:
        AFClientError is an exception that's thrown when the client library is either used improperly, or offers invalid
        data to the AutoFocus REST service
    Args:
        message (str): Message describing the error
        response (Optional[requests.Response]): Optionally the response from the server in the case of on invalid request
    """
    def __init__(self, message, response = None):
        super(AFClientError, self).__init__(self, message)
        self.response = response
        """requests.Response: response from the server (May be None)"""
        self.message = message
        """A message describing the error"""

class AFServerError(Exception):
    """
    Notes:
        AFServerError is an exception that's thrown when the AutoFocus REST service behaves unexpectedly
    Args:
        message (str): Message describing the error
        response (requests.Response): the response from the server in the case of on invalid request
    """
    def __init__(self, message, response):
        super(AFServerError, self).__init__(self, message)
        self.response = response
        """requests.Response: response from the server"""
        self.message = message
        """A message describing the error"""


class AutoFocusAPI(object):

    page_size = 2000
    search_operator = "all"

    def __init__(self, **kwargs):
        for k,v in kwargs.items():
            setattr(self, k, v)

    def __repr__(self):
        return self.__dict__.__str__()
    
    def __str__(self):
        return self.__dict__.__str__()

    @classmethod
    def _api_request(cls, path, post_data = {}, params = {}):

        if not AF_APIKEY:
            raise Exception("AF_APIKEY is not set. Library requires an APIKEY to be set")
            
        post_data["apiKey"] = AF_APIKEY
        
        resp = requests.post(_base_url + path, params = params, headers=_headers, data=json.dumps(post_data))

        if resp.status_code >= 400 and resp.status_code < 500:
            raise AFClientError(resp._content, resp)

        if resp.status_code >= 500 and resp.status_code < 600:
            raise AFServerError(resp._content, resp)

        return resp

    @classmethod
    def _api_search_request(cls, path, post_data):

        post_data["size"]   = cls.page_size
        post_data["from"]   = 0
        post_data["sort"]   = {
            "create_date": {
                "order": "desc"
            }
        }
        post_data['scope'] = "Global"

        while True:

            # There is currently a hardcoded limitation for 4000 samples per query.
            # Hardcode StopIteration until that issue is addressed
            if post_data['from'] >= 4000:
                raise StopIteration()

            if post_data['from'] + post_data['size'] > 4000:
                post_data['size'] = 4000 - post_data['from']

            # TODO: Remove the above logic once the result cap is removed

            init_query_time = time.time()
            init_query_resp = cls._api_request(path, post_data = post_data)
            init_query_data = init_query_resp.json()
            post_data['from'] += post_data['size']
            af_cookie = init_query_data['af_cookie']

            resp_data = {}
            prev_resp_data = {}
            i = 0
            while True:

                i += 1

                request_url = "/" + path.split("/")[1] + "/results/" + af_cookie

                # Try our request. Check for AF Cookie going away, which is weird
                # Catch it and add more context. Then throw it up again
                try:
                    resp = cls._api_request(request_url)
                    resp_data = resp.json()
                except AFClientError as e:
                    # TODO: Can be removed once AF Cookie going away bug is fixed.
                    if "AF Cookie Not Found" in e.message:
                        raise AFClientError("Auto Focus Cookie has gone away after %d queries taking %f seconds. Server said percent complete was at %f, last query." \
                                        % (i, time.time() - init_query_time, prev_resp_data['af_complete_percentage']), e.resp)
                    else:
                        raise e

                # If we've gotten our bucket size worth of data, or the query has complete
                if len(resp_data.get('hits', [])) == post_data['size'] \
                        or resp_data.get('af_complete_percentage', 100) == 100:
                    break

                prev_resp_data = resp_data

                continue

            if not resp_data.get('hits', None):
                raise StopIteration()

            yield resp_data

    @classmethod
    def _api_search(cls, *args, **kwargs):

        # TODO: Needs alot of documentation to make this more clear for readers

        args = list(args)

        # Classes that inherit from AutoFocusAPI need to pass a search path as the 
        # first arg to the protected _api_search method
        path = args.pop(0)

        if len(args) == 1 and type(args[0]) is str:
            post_data = {
                "query" : json.loads(args[0])
            }
        else:

            if len(args) == 1 and not kwargs:
                kwargs = args[0]

            # Just do an or here, we'll do validation below
            if "field" in kwargs or "value" in kwargs:
                args.append(kwargs)

            post_data = {
                "query": {
                    "operator": cls.search_operator,
                    "children": []
                }
            }

            for kwarg in args:        
     
                # Check and make sure field and value are passed to search - req'd
                for arg in ('field', 'value'):
                    if arg not in kwarg:
                        raise Exception

                # Build the searching paramaters to be passed to the _api_request method
                # _api_request will add the additional data needed to form a valid request
                post_data['query']['children'].append({
                    "field": kwarg['field'],
                    "operator": kwarg.get('operator', "is"),
                    "value": kwarg['value']
                })

        for res in cls._api_search_request(path, post_data = post_data):
            for hit in res['hits']:
                yield hit

class AFTag(AutoFocusAPI):

    def __init__(self, **kwargs):

        self.comments = kwargs.get("comments", NotLoaded())
        self.refs = kwargs.get("refs", NotLoaded())
        self.review = kwargs.get("review", NotLoaded())
        self.support_id = kwargs.get("support_id", NotLoaded())

        for k,v in kwargs.items():
            setattr(self, k, v)

    def __getattribute__(self, attr):

        value = object.__getattribute__(self, attr)

        # Not offered in the list controller, have to call get to lazyload:
        #      comments, refs, review, support_id
        if attr in ('comments', 'refs', 'review', 'support_id') and type(value) is NotLoaded:

            # Reloading the data via the get method
            self = AFTag.get(self.public_tag_name)
            value = object.__getattribute__(self, attr)

        return value

    @classmethod
    def list(cls, *args, **kwargs):
        """
        Args:
            scope (str): The scope of the tags you want listed, acceptable values are -
                Visible, Private, Public, Unit42, Mine, Commodity. Defaults to Visible
            sortBy (Optional[str]): The field to sort results by, acceptable values are - name, status, count, lasthit,
                upVotes, downVotes. Defaults to name
            order (str): The direction to sort, acceptable values are "asc" or "desc", Defaults to asc


        Returns:
            List[AFTag]: as list of AFTag objects based on the arguments offered.

        Raises:
            KeyError: Raises a key error when the tag does not exist
            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected

        Examples:
            for tag in AFTag.list():
                print tag.count
        """
        return AFTagFactory.list(*args, **kwargs)

    @classmethod
    def get(cls, tag_name):
        """
        Args:
            tag_name (str): The name of the tag to pull an object for

        Returns:
            AFTag: an instance of AFTag for the given tag name

        Raises:
            KeyError: Raises a key error when the tag does not exist
            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected

        Examples:
            try:
                tag = AFTag.get("Made up tag name")
            except KeyError:
                pass # Sample didn't exist
        """
        return AFTagFactory.get(tag_name)


class AFTagFactory(AutoFocusAPI):

    @classmethod
    def list(cls, *args, **kwargs):
        """
        Notes: See AFTag.list for documentation
        """

        kwargs['scope'] = kwargs.get("scope", "Visible")
        kwargs['sortBy'] = kwargs.get("sortBy", "name")
        kwargs['order'] = kwargs.get("order", "asc")
        kwargs['pageSize'] = 200
        kwargs['pageNum'] = 0

        results = []

        resp = cls._api_request("/tags/", params = kwargs).json()

        for tag in resp['tags']:
            results.append(AFTag(**tag))

        total_count = resp['total_count']

        if total_count <= kwargs['pageSize']:
            return results

        while ((kwargs['pageSize'] * kwargs['pageNum']) + kwargs['pageSize']) < total_count:

            kwargs['pageNum'] += 1

            resp = cls._api_request("/tags/", params = kwargs).json()

            for tag in resp['tags']:
                results.append(AFTag(**tag))

        return results

    @classmethod
    def get(cls, tag_name):
        """
        Notes: See AFTag.get for documentation
        """

        try:
            resp = cls._api_request("/tag/" + tag_name).json()
        except AFClientError as e:
            if e.response.code == 404:
                raise KeyError("No such tag exists")
            else:
                raise e

        return AFTag(**resp['tag'])


class AFSession(AutoFocusAPI):

    @classmethod
    def search(cls, *args, **kwargs):

        for res in cls._api_search("/sessions/search", *args, **kwargs):
            yield AFSession(**res['_source'])

class AFSampleFactory(AutoFocusAPI):

    @classmethod
    def search(cls, *args, **kwargs):
        """
        Notes: See AFSample.search documentation
        """

        for res in cls._api_search("/samples/search", *args, **kwargs):
            yield AFSample(**res['_source'])

    @classmethod
    def get(cls, hash):
        """
        Notes: See AFSample.get documentation
        """

        if not re.match(r'^([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$', hash):
            raise KeyError("Argument mush be a valid md5, sha1, or sha256 hash")

        res = None

        try:
            if len(hash) == 32:
                res = cls.search(field = "sample.md5", value = hash).next()
            elif len(hash) == 40:
                res = cls.search(field = "sample.sha1", value = hash).next()
            elif len(hash) == 64:
                res = cls.search(field = "sample.sha256", value = hash).next()
        except StopIteration:
            pass

        if not res:
            raise KeyError("No such hash found in AutoFocus")

        return res

class AFSample(object):

    """
        The AFSample is a subclass of the AutoFocusAPI class. It should NOT be instantiated
         directly. Using the various factory class methods will return instance(s) of AFSample
    """

    def __init__(self, **kwargs):

        known_attributes = ("create_date", "filetype", "malware", "md5", "sha1", "sha256", "size", "multiscanner_hit",\
                            "virustotal_hit", "source_label", "finish_date", "tag", "digital_signer", "update_date",\
                            "ssdeep", "imphash")

        # TODO: remove this when the library matures, needless checking once we sort out attributes
        for k, v in kwargs.items():
            if k not in known_attributes:
                sys.stderr.write("Unknown attribute for sample returned by REST service, please tell BSmall about this - %s:%s" % (k, v))


        #: str: md5 sum of the sample
        self.md5 = kwargs['md5']

        #: str: sha256 sum of the sample
        self.sha256 = kwargs['sha256']

        #: Optional[str]: sha1 sum of the sample
        self.sha1 = kwargs.get('sha1', None)

        #: Optional[str]: ssdeep sum of the sample
        self.ssdeep = kwargs.get('ssdeep', None)

        #: Optional[str]: imphash sum of the sample
        self.imphash = kwargs.get('imphash', None)

        #: str: The file type of the sample
        self.file_type = kwargs['filetype']

        kwargs['finish_date'] = kwargs.get('finish_date', None)
        if kwargs['finish_date']:
            datetime.strptime(kwargs['finish_date'], '%Y-%m-%dT%H:%M:%S')

        #: Optional[datetime]: The time the first sample analysis completed
        self.finish_date = kwargs['finish_date']

        kwargs['update_date'] = kwargs.get('update_date', None)
        if kwargs['update_date']:
            datetime.strptime(kwargs['update_date'], '%Y-%m-%dT%H:%M:%S')

        #: Optional[datetime]: The time the last sample analysis completed
        self.update_date = kwargs['update_date']

        # I don't think this should be optional, but playing it safe for now
        kwargs['create_date'] = kwargs.get('create_date', None)
        if kwargs['create_date']:
            datetime.strptime(kwargs['create_date'], '%Y-%m-%dT%H:%M:%S')

        #: datetime: The time the sample was first seen by the system
        self.create_date = kwargs['create_date']

        #: bool: Whether WildFire thinks the sample is Malware or not
        self.malware = True if kwargs['malware'] else False

        #: int: The size of the sample in bytes
        self.size = kwargs['size']

        #: List[AFTag]: A list of tags
        self.tags = NotLoaded()

        #: Optiona[int]: TODO needs documentation
        self.multiscanner_hits = kwargs.get("multiscanner_hit", None)

        #: Optiona[int]: how many sources regard the sample to be malicious in Virus Total
        self.virustotal_hits = kwargs.get("virustotal_hit", None)

        #: Optional[str]: The source the sample came from
        self.source_label = kwargs.get("source_label", "")

        #: Optional[str]: The signer for the sample
        self.digital_signer = kwargs.get("digital_signer", None)

        # Private _tags
        self._tags = kwargs.get('tag', None)

    def __getattribute__(self, attr):

        value = object.__getattribute__(self, attr)

        # Tags are offered as strings. Lazy load AFTag objects
        # When they are accessed
        if attr == "tags" and type(value) is NotLoaded:

            value = []

            for tag_name in self._tags:

                # TODO: Consider what might happen here if the tagname isn't in the DB
                value.append(AFTag.get(tag_name))

            self.tags = value

        return value


    def get_analyses(self, sections = ["file"], platforms = ["win7", "winxp"]):
        """
        Args:
            sections (Optional[array[str]]): The analyses sections desired.

        Returns:
            array: A list of dictionaries corresponding to the analyses in AutoFocus for the
                given sample

        Raises:
            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected
        """

        # TODO: Document all the possible sections for the sections argument

        resp = AutoFocusAPI._api_request("/sample/" + self.sha256 + "/analysis", \
                    post_data = { "sections" : sections, "platforms" : platforms }).json()

        return resp

    @classmethod
    def search(cls, *args, **kwargs):
        """
        Notes:
            Argument validation is done via the REST service. There is no client side validation of arguments. See the
            following page for details on how searching works in the UI and how to craft a query for the API:
            https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html
        Args:
            Search takes several different argument styles. See the examples to learn more.

        Yields:
            AFSample: sample objects as they are paged from the REST service

        Raises:
            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected

        Examples:
            For simple queries, keyword arguments is acceptable, for more complex or lengthy queries, it's advised to
            pass the raw string to .search

            # Arguments in the form of kwargs
            samples = []
            for sample in AFSample.search(field = "sample.malware", value = "1", operator = "is"):
                samples.append(sample.md5)

            # Python dictionary with the query parameters
            try:
                sample = AFSample.search({'field':'sample.malware', 'value':1, 'operator':'is'}).next()
            except StopIteration:
                # No results found
                pass

            # Query strings from the AutoFocus web UI
            # https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html
            sample = AFSample.search("{'field':'sample.malware', 'value':1, 'operator':'is'}").next()
        """
        for sample in AFSampleFactory.search(*args, **kwargs):
            yield sample

    @classmethod
    def get(cls, hash):
        """
        Args:
            hash (str): either a md5, sha1, or sha256 hash of the sample needed

        Returns:
            AFSample: Instance of AFSample that matches the hash offered

        Raises:
            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected
            KeyError: In the case that the argument offered is an invalid hash or that the hash
                doesn't match a sample in AutoFocus

        Examples:
            try:
                sample = AFSample.get("31a9133e095632a09a46b50f15b536dd2dc9e25e7e6981dae5913c5c8d75ce20")
                sample = AFSample.get("97a174dbc51a2c4f9cad05b6fc9af10d3ba7c919")
                sample = AFSample.get("a1f19a3ebd9213d2f0d895ec86a53390")
            except KeyError:
                pass # Sample didn't exist
        """
        return AFSampleFactory.get(hash)


if __name__ == "__main__":

    print len(AFTag.list())

    # Get a sample by hash
    sample = AFSample.get("31a9133e095632a09a46b50f15b536dd2dc9e25e7e6981dae5913c5c8d75ce20")
    for tag in sample.tags:
        print tag.public_tag_name

    sample = AFSample.get("97a174dbc51a2c4f9cad05b6fc9af10d3ba7c919")
    sample = AFSample.get("a1f19a3ebd9213d2f0d895ec86a53390")
