#!/usr/bin/env python
import requests, json, sys, time, re
from pprint import pprint
from datetime import datetime
import autofocus_config

AF_APIKEY = autofocus_config.AF_APIKEY

# A dictionaries for mapping AutoFocus Analysis Response objects
# to their corresponding normalization classes and vice-versa
_analysis_class_map = {}
_class_analysis_map = {}

ALL_ANALYSIS_SECTIONS = (
    'apk_defined_activity', 'apk_defined_intent_filter', 'apk_defined_receiver',
    'apk_defined_sensor', 'apk_defined_service', 'apk_embeded_url',
    'apk_requested_permission', 'apk_sensitive_api_call', 'apk_suspicious_api_call',
    'apk_suspicious_file', 'apk_suspicious_string', 'behavior_type', 'connection',
    'dns', 'file', 'http', 'japi', 'mutex', 'misc', 'process', 'registry','service',
    'user_agent'
)

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
    """
    NotLoaded is a class used internally by various classes in this module for handling when an attribute needs to be
    lazy loaded. This class is not meant for general use.
    """
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
        #: str: a message describing the error
        self.message = message
        #: Optional[requests.Response]: response from the server (May be None)
        self.response = response

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
        #: str: a message describing the error
        self.message = message
        #: requests.Response: response from the server
        self.response = response


class AutoFocusAPI(object):
    """
    The AutoFocusAPI is a base class for factory classes in this module to inherit from. This class is not meant for
    general use and is core to this underlying client library
    """

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
                                        % (i, time.time() - init_query_time, prev_resp_data['af_complete_percentage']), e.response)
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

# TODO: Create a class for AFTag.refs
class AFTagReference(object):
    pass

class AFTag(object):
    """
    The AFTag should be treated as read-only object matching data found in the AutoFocus REST API. It should NOT
    be instantiated directly. Instead, call the various class method factories to get instance(s) of AFTag. See:
        AFTag.list
        AFTag.get
    """

    def __init__(self, **kwargs):

        #: str: The backend compliant name for the tag. You most likely want public_name
        self.name = kwargs["tag_name"]

        #: str: the presentation name for the tag
        self.public_name = kwargs["public_tag_name"]

        #: int: the number of samples matching the tag
        self.count = kwargs["count"]

        kwargs['lasthit'] = kwargs.get('lasthit', None)

        # Preserve the raw lasthit in a private variable
        self._last_hit = kwargs['lasthit']

        if kwargs['lasthit']:
            kwargs['lasthit'] = datetime.strptime(kwargs['lasthit'], '%Y-%m-%d %H:%M:%S')

        #: Optional[datetime]: the last time there was activity witnessed for the tag
        self.last_hit = kwargs["lasthit"]

        #: str: the authors description of the tag
        self.description = kwargs["description"]

        #: str: The definition status for the tag
        self.status = kwargs["tag_definition_status"]

        #: int: The definition status id for the tag
        self.status_id = kwargs["tag_definition_status_id"]

        #: str: The definition scope for the tag
        self.scope = kwargs["tag_definition_scope"]

        #: int: The definition scoe id for the tag
        self.scope_id = kwargs["tag_definition_scope_id"]

        #: str: The class for the tag. Need to break convention for reserved words in python
        self.tag_class = kwargs.get("tag_class", NotLoaded())

        #: int: The class id for the tag. Need to break convention for reserved words in python
        self.tag_class_id = kwargs["tag_class_id"]

        #: Optiona[str]: The name of the customer who wrote the tag. Will be None if not recorded or you don't have permission to view it
        self.customer_name = kwargs.get("customer_name", None)

        #: int: up votes for the tag
        self.up_votes = kwargs.get("up_votes", 0)
        if self.up_votes == None:
            self.up_votes = 0

        #: int: Down votes for the tag
        self.down_votes = kwargs.get("down_votes", 0)
        if self.down_votes == None:
            self.down_votes = 0

        #: List[str]: Comments for the given tag
        self.comments = kwargs.get("comments", NotLoaded())

        #: List[str]: a list of references for the tag
        self.references = kwargs.get("refs", NotLoaded())

        #: dict: a dictionary with comments in it? Don't we have comments above?
        #self.review = kwargs.get("review", NotLoaded())

        #: int: The support id for the tag
        self.support_id = kwargs.get("support_id", NotLoaded())

    def __getattribute__(self, attr):

        value = object.__getattribute__(self, attr)

        # Not offered in the list controller, have to call get to lazy load:
        #      comments, refs, review, support_id
        if attr in ('comments', 'references', 'review', 'support_id', 'tag_class') and type(value) is NotLoaded:

            # Reloading the data via the get method
            self = AFTag.get(self.public_name)
            value = object.__getattribute__(self, attr)

            # Current data models are inconsistent, need to throw a warning about defaulting to None here
            # TODO: Remove this once the objects returned by the REST service are made consistent.
            if type(value) is NotLoaded:
                value = None
                sys.stderr.write("Unable to lazy load tag attribute, defaulting to None! tag:%s attribute:%s\n" % (self.public_name, attr))

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


class AFTagCache(object):

    _cache = {}

    @classmethod
    def get(cls, tag_name):

        if tag_name in cls._cache:
            return cls._cache[tag_name]

        return None

    @classmethod
    def add(cls, tag):

        cls._cache[tag.public_name] = tag
        return cls._cache[tag.public_name]

    @classmethod
    def clear(cls, tag):

        cls._cache[tag.public_name] = {}


class AFTagFactory(AutoFocusAPI):
    """
    AFTagFactory is a class to handle fetching an instantiating AFTag objects. See AFTag for details
    """

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

        resp_data = cls._api_request("/tags/", params = kwargs).json()

        for tag_data in resp_data['tags']:
            results.append(AFTag(**tag_data))

        total_count = resp_data['total_count']

        if total_count <= kwargs['pageSize']:
            return results

        while ((kwargs['pageSize'] * kwargs['pageNum']) + kwargs['pageSize']) < total_count:

            kwargs['pageNum'] += 1

            resp_data = cls._api_request("/tags/", params = kwargs).json()

            for tag_data in resp_data['tags']:
                results.append(AFTag(**tag_data))

        return results

    @classmethod
    def get(cls, tag_name):
        """
        Notes: See AFTag.get for documentation
        """

        tag = AFTagCache.get(tag_name)

        if not tag:

            try:
                resp = cls._api_request("/tag/" + tag_name).json()
            except AFClientError as e:
                if e.response.code == 404:
                    raise KeyError("No such tag exists")
                else:
                    raise e

            tag = AFTagCache.add(AFTag(**resp['tag']))

        return tag


class AFSession(AutoFocusAPI):

    @classmethod
    def search(cls, *args, **kwargs):

        for res in cls._api_search("/sessions/search", *args, **kwargs):
            yield AFSession(**res['_source'])

class AFSampleFactory(AutoFocusAPI):
    """
    AFSampleFactory is a class to handle fetching an instantiating AFSample objects. See AFSample for details
    """

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
    The AFSample should be treated as read-only object matching data found in the AutoFocus REST API. It should NOT
    be instantiated directly. Instead, call the various class method factories to get instance(s) of AFSample. See:
        AFSample.search
        AFSample.get
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
            kwargs['finish_date'] = datetime.strptime(kwargs['finish_date'], '%Y-%m-%dT%H:%M:%S')

        #: Optional[datetime]: The time the first sample analysis completed
        self.finish_date = kwargs['finish_date']

        kwargs['update_date'] = kwargs.get('update_date', None)
        if kwargs['update_date']:
            kwargs['update_date'] = datetime.strptime(kwargs['update_date'], '%Y-%m-%dT%H:%M:%S')

        #: Optional[datetime]: The time the last sample analysis completed
        self.update_date = kwargs['update_date']

        # I don't think this should be optional, but playing it safe for now
        kwargs['create_date'] = kwargs.get('create_date', None)
        if kwargs['create_date']:
            kwargs['create_date'] = datetime.strptime(kwargs['create_date'], '%Y-%m-%dT%H:%M:%S')

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


    def get_analyses(self, sections = None, platforms = ["win7", "winxp", "staticAnalyzer"]):
        """
        Args:
            sections (Optional[array[str]]): The analysis sections desired. Defaults to all possible sections.
            platforms (Optional[array[str]]): The analysis platforms desired. Defaults to all possible platforms.

        Returns:
            array[AutoFocusAnalysis]: A list of AutoFocusAnalysis sub-class instances representing the analysis

        Raises:
            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected
        """

        if not sections:
            sections = ALL_ANALYSIS_SECTIONS

        resp_data = AutoFocusAPI._api_request("/sample/" + self.sha256 + "/analysis", \
                    post_data = { "sections" : sections, "platforms" : platforms }).json()

        analyses = []

        for section in resp_data['sections']:
            af_analysis_class = _analysis_class_map.get(section, None)

            if not af_analysis_class:
                raise AFClientError("Was expecting a known section in analysis_class_map, got {} instead".format(section))

#            for platform in resp_data['platforms']: # staticAnlyzer is being returned by isn't in the set?
            for platform in resp_data[section].keys():
                for data in resp_data[section][platform]:
                    # TODO: remove try catch when all analyses types are normalized
                    try:
                        analyses.append(af_analysis_class.parse_auto_focus_response(platform, data))
                    except NotImplementedError:
                        pass

        return analyses

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

    # TODO: Convenience method to handle searching multiple hashes (Have to do crazy paging to get more than 100 or 10000)
    @classmethod
    def search_hashes(cls, hashes):
        raise NotImplemented

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

class AutoFocusAnalysis(object):

    def __init__(self, obj_data):
        for k,v in obj_data.items():
            setattr(self, k, v)

    @classmethod
    def parse_auto_focus_response(cls, platform, resp_data):
        return cls(resp_data)

#apk_defined_activity
class AFApkActivityAnalysis(AutoFocusAnalysis):
    pass

#apk_defined_intent_filter
class AFApkIntentFilterAnalysis(AutoFocusAnalysis):
    pass

#apk_defined_receiver
class AFApkReceiverAnalysis(AutoFocusAnalysis):
    pass

#apk_defined_sensor
class AFApkSensorAnalysis(AutoFocusAnalysis):
    pass

#apk_defined_service
class AFApkServiceAnalysis(AutoFocusAnalysis):
    pass

#apk_embeded_url
class AFApkEmbededUrlAnalysis(AutoFocusAnalysis):
    pass

#apk_requested_permission
class AFApkRequestedPermissionAnalysis(AutoFocusAnalysis):
    pass

#apk_sensitive_api_call
class AFApkSensitiveApiCallAnalysis(AutoFocusAnalysis):
    pass

#apk_suspicious_api_call
class AFApkSuspiciousApiCallAnalysis(AutoFocusAnalysis):
    pass

#apk_suspicious_file
class AFApkSuspiciousFileAnalysis(AutoFocusAnalysis):
    pass

#apk_suspicious_string
class AFApkSuspiciousStringAnalysis(AutoFocusAnalysis):
    pass

#behavior_type
class AFBehaviorTypeAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, behavior):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: str: A string representing a behavior the sample exhibits
        self.behavior = behavior

    @classmethod
    def parse_auto_focus_response(cls, platform, conn_data):

        ba = cls(platform, conn_data['line'])
        ba._raw_line = conn_data['line']

        return ba

#connection
class AFConnectionAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, process_name, src_port, dst_ip, dst_port, protocol, action, country_code, \
                 benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional(str): The destination IP for the connection. Only valid for outbound connections
        self.dst_ip = dst_ip

        #: Optional(int): The destination port for the connection. Only valid for outbound connections
        self.dst_port = dst_port

        #: Optional(int): The source port for the connection. Only valid for listening connections
        self.src_port = src_port

        #: str: The protocol of the connection
        self.protocol = protocol

        #: Optional[str]: The name of the process that created the connection, when available
        self.process_name = process_name

        #: Optional[str]: The country code for the destionation IP, when available
        self.country_code = country_code

        #: str: The action related to the connection (listen or connect)
        self.action = action

    @classmethod
    def parse_auto_focus_response(cls, platform, conn_data):

        (dst_ip, src_port, dst_port, uk2, country_code) = (None, None, None, None, None)
        line_parts = conn_data['line'].split(" , ")

        if len(line_parts) >= 4:
            if len(line_parts) > 4:
                (process_name, protocol, dst_ip_port, uk2, country_code) = line_parts[0:5]
            else:
                (process_name, protocol, dst_ip_port, country_code) = line_parts[0:4]
            (dst_ip, dst_port) = dst_ip_port.split(":")
        elif len(line_parts) == 3:
            (process_name, protocol, src_port) = line_parts[0:3]

        if process_name.lower() == "unknown":
            process_name = None

        if country_code == "" or country_code == "N/A":
            country_code = None

        (benign_c, malware_c, grayware_c) = (conn_data.get('b', 0), conn_data.get('m', 0), conn_data.get('g', 0))

        protocol = protocol.lower()

        action = "connect"
        if "-" in protocol:
            (protocol, action) = protocol.split("-")

            if action == "connection":
                action = "connect"
            elif action == "listening":
                action = 'listen'
            else:
                #TODO remove this and throw an exception when we are confident about our normalization
                sys.stderr.write("Unknown connection action {} -- tell BSMALL".format(action))

        #TODO remove this and throw an exception when we are confident about our normalization
        if protocol not in ('tcp', 'udp', 'icmp', 'gre'):
            sys.stderr.write("Unknown protocol {} -- tell BSMALL".format(protocol))

        ca = cls(platform, process_name, src_port, dst_ip, dst_port, protocol, action, country_code, benign_c, \
                 malware_c, grayware_c)
        ca._raw_line = conn_data['line']

        return ca

#dns
class AFDnsAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, query, response, type, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string of the query preformed
        self.query = query

        #: str: The response from the query performed
        self.response = response

        #: str: The type of request performed
        self.type = type

    @classmethod
    def parse_auto_focus_response(cls, platform, dns_data):

        line_parts = dns_data['line'].split(" , ")
        (query, response, type) = line_parts[0:3]
        (benign_c, malware_c, grayware_c) = (dns_data.get('b', 0), dns_data.get('m', 0), dns_data.get('g', 0))

        da = cls(platform,query, response, type, benign_c, malware_c, grayware_c)
        da._raw_line = dns_data['line']

        return da

#file
class AFFileAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, process_name, file_action, file_name, benign, malware, grayware):
        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The process name that has attempted access the file
        self.process_name = process_name

        #: str: The attempted action taken on a file
        self.file_action = file_action

        #: str: The affected file's name
        self.file_name = file_name

    @classmethod
    def parse_auto_focus_response(cls, platform, file_data):

        line_parts = file_data['line'].split(" , ")
        (process_name, file_action, file_name) = line_parts[0:3]
        (benign_c, malware_c, grayware_c) = (file_data.get('b', 0), file_data.get('m', 0), file_data.get('g', 0))

        fa = cls(platform, process_name, file_action, file_name, benign_c, malware_c, grayware_c)
        fa._raw_line = file_data['line']

        return fa

#http
class AFHttpAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, host, method, url, user_agent, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The host the HTTP connection was made to
        self.host = host

        #: str: The method used in the requesty
        self.method = method

        #: str: The url of the request
        self.url = url

        #: str: The user agent of the request
        self.user_agent = user_agent

    @classmethod
    def parse_auto_focus_response(cls, platform, http_data):

        line_parts = http_data['line'].split(" , ", 3)
        (host, method, url, user_agent) = line_parts[0:4]
        (benign_c, malware_c, grayware_c) = (http_data.get('b', 0), http_data.get('m', 0), http_data.get('g', 0))

        ha = cls(platform,host, method, url, user_agent, benign_c, malware_c, grayware_c)
        ha._raw_line = http_data['line']

        return ha

#japi
class AFJavaApiAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, activity, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        # TODO: Very generic. Needs more context
        #: str: A string representing java API activity
        self.activity = activity

    @classmethod
    def parse_auto_focus_response(cls, platform, japi_data):

        (benign_c, malware_c, grayware_c) = (japi_data.get('b', 0), japi_data.get('m', 0), japi_data.get('g', 0))

        ja = cls(platform, japi_data['line'], benign_c, malware_c, grayware_c)
        ja._raw_line = japi_data['line']

        return ja

#mutex
class AFMutexAnalysis(AutoFocusAnalysis):
    pass

#misc
class AFMiscellaneousAnalysis(AutoFocusAnalysis):
    pass

#process
class AFProcessAnalysis(AutoFocusAnalysis):
    pass

#registry
class AFRegistryAnalysis(AutoFocusAnalysis):
    pass

#service
class AFServiceAnalysis(AutoFocusAnalysis):
    pass

#user_agent
class AFUserAgentAnalysis(AutoFocusAnalysis):
    pass

_analysis_class_map['apk_defined_activity'] = AFApkActivityAnalysis
_analysis_class_map['apk_defined_intent_filter'] = AFApkIntentFilterAnalysis
_analysis_class_map['apk_defined_receiver'] = AFApkReceiverAnalysis
_analysis_class_map['apk_defined_sensor'] = AFApkSensorAnalysis
_analysis_class_map['apk_defined_service'] = AFApkServiceAnalysis
_analysis_class_map['apk_embeded_url'] = AFApkEmbededUrlAnalysis
_analysis_class_map['apk_requested_permission'] = AFApkRequestedPermissionAnalysis
_analysis_class_map['apk_sensitive_api_call'] = AFApkSensitiveApiCallAnalysis
_analysis_class_map['apk_suspicious_api_call'] = AFApkSuspiciousApiCallAnalysis
_analysis_class_map['apk_suspicious_file'] = AFApkSuspiciousFileAnalysis
_analysis_class_map['apk_suspicious_string'] = AFApkSuspiciousStringAnalysis
_analysis_class_map['behavior_type'] = AFBehaviorTypeAnalysis
_analysis_class_map['connection'] = AFConnectionAnalysis
_analysis_class_map['dns'] = AFDnsAnalysis
_analysis_class_map['file'] = AFFileAnalysis
_analysis_class_map['http'] = AFHttpAnalysis
_analysis_class_map['japi'] = AFJavaApiAnalysis
_analysis_class_map['mutex'] = AFMutexAnalysis
_analysis_class_map['misc'] = AFMiscellaneousAnalysis
_analysis_class_map['process'] = AFProcessAnalysis
_analysis_class_map['registry'] = AFRegistryAnalysis
_analysis_class_map['service'] = AFServiceAnalysis
_analysis_class_map['user_agent'] = AFUserAgentAnalysis

for k,v in _analysis_class_map.items():
    _class_analysis_map[v] = k


# Platforms
# win7, winxp, staticAnalyzer


if __name__ == "__main__":

    # Java API  Analysis
    sample = AFSample.get("2b69dcee474f802bab494983d1329d2dc3f7d7bb4c9f16836efc794284276c8e")

    for analysis in sample.get_analyses(['japi']):
        print type(analysis)

#    # HTTP Analysis
#    sample = AFSample.get("c1dc94d92c0ea361636d2f08b63059848ec1fb971678bfc34bcb4a960a120f7e")
#
#    for analysis in sample.get_analyses(['http']):
#        print type(analysis)

#    # DNS Analysis
#    sample = AFSample.get("21e5053f89c89c6f71e8028f20139f943f75f8d78210404501d79bae85ac6500")
#
#    for analysis in sample.get_analyses(['dns']):
#        print type(analysis)

    # Behavior analysis
#    sample = AFSample.get("438ea5ec331b15cb5bd5bb57b760195734141623d83a03ffd5c6ec7f13ddada9")
#
#    for analysis in sample.get_analyses(['behavior_type']):
#        print type(analysis)


    # Connection testing hashes

#    test_hashes = (
#        "7a1f5a5fe0a3bd5031da504d67e224f35b96fd1fd9771f67bc0936999d4d292b", # Has udp
#        "90c6cef834a7528e6771959c2e093c230866167eb8d1f16362a5128c0c35694f", # Has tcp-connection, udp-connection
#        "0bb615a781035e4d0143582ea5a0a4c9486625585de1cd8e3a8669cd2a1b29f3"  # Has tcp-listen
#    )
#
#    # Get a sample by hash
#    for sample_hash in test_hashes:
#
#        sample = AFSample.get(sample_hash)
#
#        for analysis in sample.get_analyses(['connection']):
#            print type(analysis)
#
##        for tag in sample.tags:
##            print tag.public_name
#
#    for sample in AFSample.search('{"operator":"all","children":[{"field":"sample.tasks.connection","operator":"contains","value":"tcp"},{"field":"sample.tag_scope","operator":"is","value":"unit42"}]}'):
#
#        for analysis in sample.get_analyses(['connection']):
#
#            print type(analysis)
