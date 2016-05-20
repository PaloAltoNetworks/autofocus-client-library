#!/usr/bin/env python
import requests, json, sys, time, re, os, math, decimal
from pprint import pprint
from datetime import datetime, date

AF_APIKEY = None

try:
    import ConfigParser
    parser = ConfigParser.ConfigParser()
    conf_path = os.environ.get("PANW_CONFIG", "~/.config/panw")
    parser.read(os.path.expanduser(conf_path))
    AF_APIKEY = parser.get("autofocus", "apikey")
except:
    sys.stderr.write("No AutoFocus API key found in ~/.config/panw. Please remember to specify your API key manually " +
                     "before utilizing the API\n")

__all__ = [
    'AFApiActivity','AFApkActivityAnalysis','AFApkEmbededUrlAnalysis','AFApkIntentFilterAnalysis'
    'AFApkReceiverAnalysis','AFApkRequestedPermissionAnalysis','AFApkSensitiveApiCallAnalysis',
    'AFApkSensorAnalysis','AFApkServiceAnalysis','AFApkSuspiciousApiCallAnalysis'
    'AFApkSuspiciousFileAnalysis','AFApkSuspiciousStringAnalysis', 'AFBehaviorTypeAnalysis','AFClientError'
    'AFConnectionActivity','AFDnsActivity','AFFileActivity','AFHttpActivity'
    'AFJavaApiActivity','AFMutexActivity','AFProcessActivity','AFRegistryActivity'
    'AFSample','AFSampleFactory','AFSampleAbsent','AFServerError'
    'AFServiceActivity','AFSession','AFTag','AFTagCache'
    'AFTagFactory','AFTagReference','AFUserAgentFragment','AutoFocusAnalysis'
    'AutoFocusAPI','AutoFocusObject'
 ]

# Useful information:
#
# * We're not doing any input validation in the client itself. We pass
#   the data to the API, and rely on 4XX errors to communicate invalid
#   requests. At the time this was written, the API DOES NOT validate search
#   values. So you can offer invalid IPs, such as 592.99.1.1 and it will
#   not balk. The result set will be empty, naturally.

_USER_AGENT =  "GSRT AutoFocus Client Library/1.0"

ALL_ANALYSIS_SECTIONS = (
    'apk_defined_activity', 'apk_defined_intent_filter', 'apk_defined_receiver',
    'apk_defined_sensor', 'apk_defined_service', 'apk_embeded_url',
    'apk_requested_permission', 'apk_sensitive_api_call', 'apk_suspicious_api_call',
    'apk_suspicious_file', 'apk_suspicious_string', 'behavior_type', 'connection',
    'dns', 'file', 'http', 'japi', 'mutex', 'misc', 'process', 'registry','service',
    'user_agent'
)

# A dictionaries for mapping AutoFocus Analysis Response objects
# to their corresponding normalization classes and vice-versa
_analysis_class_map = {}
_class_analysis_map = {}

_base_url = "https://autofocus.paloaltonetworks.com/api/v1.0"

class GrauduatingSleepError(Exception):
    pass

class GraduatingSleep(object):

    init_sleep_duration = .1
    max_sleep_duration = 600

    def __init__(self):

        self.counter = 0

        self.total_sleep_time = 0

    def sleep(self):

        # Graduating sleep time. Sleep for progressively longer until we get results. This logic will allow us to
        # check results up to 185 times within 10 minutes. If we haven't gotten a full result set in 10 minutes,
        # raise an exception
        sleep_time = self.__class__.init_sleep_duration
        sleep_time += sleep_time * math.floor(self.counter / 3)

        self.total_sleep_time += sleep_time

        if self.total_sleep_time >= self.__class__.max_sleep_duration:
            raise GrauduatingSleepError()

        time.sleep(sleep_time)

        self.counter += 1

class NotLoaded(object):
    """
    NotLoaded is a class used internally by various classes in this module for handling when an attribute needs to be
    lazy loaded. This class is not meant for general use.
    """
    pass

class AutoFocusException(Exception):
    pass

class AFRedirectError(AutoFocusException):
    """
    Notes:
        AFRedirectError is an exception that's thrown when the client library is being redirected. All URLs should be
        direct and not require a redirect
    Args:
        message (str): Message describing the error
        response (requests.Response): The response from the server in the case of on invalid request
    """
    def __init__(self, message, response):
        #: str: a message describing the error
        self.message = message
        #: requests.Response: response from the server
        self.response = response

class AFClientError(AutoFocusException):
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

class AFServerError(AutoFocusException):
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

class AFSampleAbsent(AutoFocusException, KeyError):
    pass

class AFTagAbsent(AutoFocusException, KeyError):
    pass

class _InvalidSampleData(Exception):
    """
    Private class meant to be used for skipping bad sample rows
    """
    pass

class _InvalidAnalysisData(Exception):
    """
    Private class meant to be used for skipping bad analysis data rows
    """
    pass

class AutoFocusObject(object):
    def serialize(self, depth=1, include_all=True):
        """ Converts object to a dictionary representation. Depending on combination
            of depth and include_all parameters, performance on serialization may suffer,
            especially if trying to serialize many objects. Using a lower depth and/or setting
            include_all to False will reduce the number of API calls made during serialization

            Args:
                depth: how many nested objects to include in dictionary
                include_all: whether or not to include lazy loaded attributes.

            Returns:
                dictionary containing attributes and values
        """
        serialized = {}

        # stop if we hit specified depth
        if depth == 0:
            return None

        # decide if we should include or not include attributes based on lazy loading
        blacklist = []
        for k in self.__dict__:
            if include_all:
                # lazy load everything and include it
                getattr(self, k)
            else:
                # don't include lazy loaded attributes
                raw_value = super(AutoFocusObject, self).__getattribute__(k)
                if isinstance(raw_value, NotLoaded):
                    blacklist.append(k)

        # serialize
        for k, v in self.__dict__.items():

            # ignore private and blacklisted
            if k.startswith("_") or k in blacklist:
                continue

            if isinstance(v, list):
                serialized_array = []
                for item in v:
                    if isinstance(item, AutoFocusObject):
                        if depth > 1:
                            serialized_array.append(item.serialize(depth=depth-1))
                    elif isinstance(item, (datetime, date)):
                        serialized_array.append(item.isoformat())
                    elif isinstance(item, decimal.Decimal):
                        serialized_array.append("%.1f" % item)
                    elif isinstance(item, (str, int, dict)):
                        serialized_array.append(item)
                serialized[k] = serialized_array

            elif isinstance(v, AutoFocusObject):
                # only encode hard coded relations (via __serializable_relations__)
                # to prevent huge data returns and infinite loops
                if depth > 1:
                    serialized[k] = v.serialize(depth=depth-1)
            else:
                if isinstance(v, (datetime, date)):
                    serialized[k] = v.isoformat()
                elif isinstance(v, decimal.Decimal):
                    serialized[k] = "%.1f" % v
                else:
                    serialized[k] = v

        return serialized

class AutoFocusAPI(object):
    """
    The AutoFocusAPI is a base class for factory classes in this module to inherit from. This class is not meant for
    general use and is core to this underlying client library
    """
    api_key = None
    page_size = 2000

    def __init__(self, **kwargs):
        for k,v in kwargs.items():
            setattr(self, k, v)

    def __repr__(self):
        return self.__dict__.__str__()
    
    def __str__(self):
        return self.__dict__.__str__()

    @classmethod
    def _api_request(cls, path, post_data = {}, params = {}):

        if not AutoFocusAPI.api_key:
            AutoFocusAPI.api_key = AF_APIKEY

        if not AutoFocusAPI.api_key:
            raise AFClientError("AF_APIKEY is not set. Library requires an APIKEY to be set")
            
        post_data["apiKey"] = AutoFocusAPI.api_key

        headers = {
            "Content-Type" : "application/json",
            "User-Agent" : _USER_AGENT
        }

        resp = requests.post(_base_url + path, params = params, headers=headers, data=json.dumps(post_data),
                             allow_redirects = False)

        if resp.status_code >= 300 and resp.status_code < 400:
            raise AFRedirectError("Unexpected redirect", resp)

        if resp.status_code >= 400 and resp.status_code < 500:
            raise AFClientError(resp._content, resp)

        if resp.status_code >= 500 and resp.status_code < 600:
            raise AFServerError(resp._content, resp)

        return resp

    @classmethod
    def _api_count_request(cls, path,  post_data):

        # Be gentle, we're only going to pull 1 sample, since we're not using it
        post_data['size'] = 1
        post_data['from'] = 0

        init_query_time = time.time()
        init_query_resp = cls._api_request(path, post_data = post_data)
        init_query_data = init_query_resp.json()
        af_cookie = init_query_data['af_cookie']

        sleeper = GraduatingSleep()

        # We'll poll the result bucket until we get a complete query and then we'll return the count
        while True:

            request_url = "/" + path.split("/")[1] + "/results/" + af_cookie

            # Try our request. Check for AF Cookie going away, which is weird
            # Catch it and add more context. Then throw it up again
            try:
                resp = cls._api_request(request_url)
                resp_data = resp.json()
            except AFClientError as e:
                e.message = "AF_COOKIE - {}\n".format(af_cookie) + e.message
                raise e
            except AFServerError as e:
                e.message = "AF_COOKIE - {}\n".format(af_cookie) + e.message
                raise e

            # If we've gotten our bucket size worth of data, or the query has complete
            if resp_data.get('af_complete_percentage', 100) == 100:
                return resp_data['total']

            try:
                sleeper.sleep()
            except GrauduatingSleepError:
                raise AFServerError("AF_COOKIE - {}\nTimed out while pulling results".format(af_cookie), resp)

    @classmethod
    def _api_scan_request(cls, path, post_data):

        post_data["size"] = post_data.get("size", cls.page_size)

        actual_res_count = 0

        init_query_resp = cls._api_request(path, post_data = post_data)
        init_query_data = init_query_resp.json()
        af_cookie = init_query_data['af_cookie']

        sleeper = GraduatingSleep()

        while True:

            request_url = "/" + path.split("/")[1] + "/results/" + af_cookie
            resp = cls._api_request(request_url)
            resp_data = resp.json()

            # We should always have 'af_complete_percentage' in resp_data.
            # In the case that we do have it, and the value is not 0 perecent complete, then we should also have
            # 'total' in the resp_data
            if 'af_complete_percentage' not in resp_data or \
                    (resp_data['af_complete_percentage'] and 'total' not in resp_data):
                raise AFServerError("AF_COOKIE - {}\nServer sent malformed response".format(af_cookie), resp)

            #prev_resp_data = resp_data

            actual_res_count += len(resp_data.get('hits', []))

            if 'hits' in resp_data:
                yield resp_data

            # If we've gotten to 100%, it's time to stop iteration
            if resp_data['af_complete_percentage'] == 100:

                if actual_res_count != resp_data['total']:
                    # Sanity check
                    raise AFServerError("AF_COOKIE - {}\nExpecting {} results, but actually got {} while scanning"
                                            .format(af_cookie, resp_data['total'], actual_res_count), resp)
                raise StopIteration()

            try:
                sleeper.sleep()
            except GrauduatingSleepError:
                raise AFServerError("AF_COOKIE - {}\nTimed out while pulling results".format(af_cookie), resp)

    @classmethod
    def _api_search_request(cls, path,  post_data):

        post_data["size"] = post_data.get("size", cls.page_size)
        post_data["from"] = 0

        while True:

            # Trim the page for the 4k limit on regular searches
            if "type" not in post_data or post_data['type'] != "scan":

                if post_data['from'] >= 4000:
                    raise StopIteration()

                if post_data['from'] + post_data['size'] > 4000:
                    post_data['size'] = 4000 - post_data['from']

            init_query_time = time.time()
            init_query_resp = cls._api_request(path, post_data = post_data)
            init_query_data = init_query_resp.json()
            post_data['from'] += post_data['size']
            af_cookie = init_query_data['af_cookie']

            resp_data = {}
            prev_resp_data = {}

            sleeper = GraduatingSleep()

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
                        e.message = "AF_COOKIE - {}\n".format(af_cookie) + e.message
                        raise e
                except AFServerError as e:
                    e.message = "AF_COOKIE - {}\n".format(af_cookie) + e.message
                    raise e

                # If we've gotten our bucket size worth of data, or the query has complete
                if len(resp_data.get('hits', [])) == post_data['size'] \
                        or resp_data.get('af_complete_percentage', 100) == 100:
                    break

                prev_resp_data = resp_data

                try:
                    sleeper.sleep()
                except GrauduatingSleepError:
                    raise AFServerError("AF_COOKIE - {}\nTimed out while pulling results".format(af_cookie), resp)

            if not resp_data.get('hits', None):
                raise StopIteration()

            yield resp_data

    @classmethod
    def _prep_post_data(cls, query, scope, size = None, sort_by = None, sort_dir = None):

        post_data = {}

        if scope:
            post_data["scope"] = scope

        if size:
            post_data['size'] = size

        if sort_by:
            post_data['sort'] = {
                sort_by: {
                    "order": sort_dir if sort_dir else "asc"
                }
            }

        if type(query) is str or type(query) is unicode:
            post_data['query'] = json.loads(query)
        elif type(query) is dict:
            if 'field' in query:
                post_data['query'] = { "operator" : "all", "children" : [query]}
            else:
                post_data['query'] = query
        else:
            raise ValueError("Query must be a valid AutoFocus search string or object (dictionary)")

        return post_data

    @classmethod
    def _api_count(cls, path, query, scope):

        post_data = cls._prep_post_data(query, scope)

        return cls._api_count_request(path, post_data)

    @classmethod
    def _api_scan(cls, path, query, scope, page_size):

        post_data = cls._prep_post_data(query, scope, size = page_size)

        post_data['type'] = "scan"

        for res in cls._api_scan_request(path, post_data):
            for hit in res['hits']:
                yield hit

    @classmethod
    def _api_search(cls, path, query, scope, sort_by, sort_dir):

        post_data = cls._prep_post_data(query, scope, sort_by = sort_by, sort_dir = sort_dir)

        for res in cls._api_search_request(path, post_data):
            for hit in res['hits']:
                yield hit

# TODO: Create a class for AFTag.refs
class AFTagReference(AutoFocusObject):
    pass

class AFTag(AutoFocusObject):
    """
    Notes:
        The AFTag should be treated as read-only object matching data found in the AutoFocus REST API. It should NOT
        be instantiated directly. Instead, call the various class method factories to get instance(s) of AFTag. See:
        * autofocus.AFTag.list
        * autofocus.AFTag.get
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
            AFSampleAbsent: Raises a key error when the tag does not exist
            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected

        Examples:
            try:
                tag = AFTag.get("Made up tag name")
            except AFTagAbsent:
                pass # Tag didn't exist
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

        kwargs['scope'] = kwargs.get("scope", "visible").lower()
        kwargs['sortBy'] = kwargs.get("sortBy", "name")
        kwargs['order'] = kwargs.get("order", "asc")
        kwargs['pageSize'] = 200
        kwargs['pageNum'] = 0

        results = []

        resp_data = cls._api_request("/tags/", post_data = kwargs).json()

        for tag_data in resp_data['tags']:
            results.append(AFTag(**tag_data))

        total_count = resp_data['total_count']

        if total_count <= kwargs['pageSize']:
            return results

        while ((kwargs['pageSize'] * kwargs['pageNum']) + kwargs['pageSize']) < total_count:

            kwargs['pageNum'] += 1

            resp_data = cls._api_request("/tags/", post_data = kwargs).json()

            for tag_data in resp_data['tags']:
                results.append(AFTagCache.add(AFTag(**tag_data)))

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
                if e.response.status_code == 404:
                    raise AFTagAbsent("No such tag exists")
                else:
                    raise e

            tag = AFTagCache.add(AFTag(**resp['tag']))

        return tag

class AFSession(AutoFocusObject):

    def __init__(self, **kwargs):
        """
        The AFSession should be treated as read-only object matching data found in the AutoFocus REST API. It should NOT
        be instantiated directly. Instead, call the class method factorty to get instance(s) of AFSession. See:
        - :func:`AFSession.search`
        """

        #: str: The application this session activity was related to
        self.application = kwargs.get("app")

        #: str: The account name for the device (regular users will only see their account)
        self.account_name = kwargs.get("device.acctname")

        #: str: The country code where the device detecting the activity exists
        self.device_country_code = kwargs.get("device.countrycode")

        #: str: The country where the device detecting the activity exists
        self.device_country = kwargs.get("device.country")

        #: str: The hostname of the device detecting the activity
        self.device_hostname = kwargs.get("device.hostname")

        #: str: The business industry that the activity was detected on
        self.industry = kwargs.get("device.industry")

        #: str: The line of business that the activity was detected on
        self.business_line = kwargs.get("device.lob")

        #: str: The model of the device reporting the activity
        self.device_model = kwargs.get("device.model")

        #: str: The serial number of the device reporting activity
        self.device_serial = kwargs.get("device.serial")

        #: str: The version of the device reporting activity
        self.device_version = kwargs.get("device.swver")

        #: str: The country code of the destination
        self.dst_country_code = kwargs.get("dst.countrycode")

        #: str: The country of the destination
        self.dst_country = kwargs.get("dst.country")

        #: str: The destination IP address
        self.dst_ip = kwargs.get("dst.ip")

        #: bool: true/false whether the IP is private
        self.dst_is_private_ip = True if kwargs.get("dst.isprivateip") else False

        #: int: the destination port of the activity
        self.dst_port = kwargs.get("dst.port")

        #: str: the destination address(es) of the email
        self.email_recipient = kwargs.get("emailrecipient")

        #: str: characterset of the email subject
        self.email_charset = kwargs.get("emailsbjcharset", "")

        #: str: originating address for the email
        self.email_sender = kwargs.get("emailsender")

        #: str: characterset of the email subject
        self.email_subject = kwargs.get("emailsubject")

        #: str: the file name of the sample resulting in this activity
        self.file_name = kwargs.get("filename")

        #: str: the URL the file originated from
        self.file_url = kwargs.get("fileurl")

        #: bool: true/false whether the sample was manually uploaded to wildfire
        self.is_uploaded = True if kwargs.get("isuploaded") else False

        #: str: the sha256 hash fo the related sample
        self.sha256 = kwargs.get("sha256")

        #: str: The country code of the source
        self.src_country_code = kwargs.get("src.countrycode")

        #: str: The country of the source
        self.src_country = kwargs.get("src.country")

        #: str: The source IP address
        self.src_ip = kwargs.get("src.ip")

        #: bool: true/false whether the IP is private
        self.src_is_private_ip = True if kwargs.get("src.isprivateip") else False

        #: int: the destination port of the activity
        self.src_port = kwargs.get("src.port")

        timestamp = kwargs.get("tstamp")
        self._raw_timestamp = timestamp

        if timestamp:
            timestamp = timestamp.split(".")[0]
            timestamp = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S')

        #: datetime: the time the activity was detected
        self.timestamp = timestamp

        # Doesn't seem to have much meaing. Making private
        self._user_id = kwargs.get("user_id")

        # Doesn't seem to have much meaing. Making private
        self._vsys = kwargs.get("vsys")

    @classmethod
    def scan(cls, query, page_size = 20000):
        """

        The AFSession.scan method is a factory to return AFSession object instances. These correspond to values returned
        by the query supplied.

        Notes
        -----
            This method is identical to the search method, except it allows for returning results beyond the 4000
            match limit imposed on search. This method does not allow for sorting and can potentially return extremely
            large result sets.

            Argument validation is done via the REST service. There is no client side validation of arguments. See the
            `following page <https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html>`_
            for details on how searching works in the UI and how to craft a query for the API.

        Examples
        --------
            Using the search class method::

                # Query strings from the AutoFocus web UI
                # https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html
                try:
                    for session in AFSession.scan({'field':'session.malware', 'value':1, 'operator':'is'}):
                        pass # Do something with the session
                except AFServerError:
                    pass # Something happened to the server
                except AFClientError:
                    pass # The client did something stupid, likely a bad query was passed

                # Python dictionary with the query parameters
                try:
                    session = AFSession.search({'field':'session.malware', 'value':1, 'operator':'is'}).next()
                except StopIteration:
                    pass # No results found
                except AFServerError:
                    pass # Something happened to the server
                except AFClientError:
                    pass # The client did something stupid, likely a bad query was passed
        Args:
            query str: The query to run against autofocus (will also take dicts per examples)

        Yields:
            AFSession: sample objects as they are paged from the REST service

        Raises
        ------
            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected

        """
        for res in AFSessionFactory.scan(query, page_size):
            yield res

    @classmethod
    def count(cls, query):
        """

        The AFSession.count method returns the count of sessions matching the query offered

        Notes
        -----
            Argument validation is done via the REST service. There is no client side validation of arguments. See the
            `following page <https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html>`_
            for details on how searching works in the UI and how to craft a query for the API.

        Examples
        --------
            Using the search class method::

                # Query strings from the AutoFocus web UI
                # https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html
                try:
                    session_count = AFSession.count({'field':'session.malware', 'value':1, 'operator':'is'}):
                        pass # Do something with the session
                except AFServerError:
                    pass # Something happened to the server
                except AFClientError:
                    pass # The client did something stupid, likely a bad query was passed

                # Python dictionary with the query parameters
                try:
                    session = AFSession.count({'field':'session.malware', 'value':1, 'operator':'is'})
                except StopIteration:
                    pass # No results found
                except AFServerError:
                    pass # Something happened to the server
                except AFClientError:
                    pass # The client did something stupid, likely a bad query was passed
        Args:
            query str: The query to run against autofocus (will also take dicts per examples)

        Returns:
            int: the number of sessions matching the query

        Raises
        ------
            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected

        """
        return AFSessionFactory.count(query)

    @classmethod
    def search(cls, query, sort_by = "tstamp", sort_order = "asc"):
        """

        The AFSession.search method is a factory to return AFSession object instances. These correspond to values returned
        by the query supplied.

        Notes
        -----
            Argument validation is done via the REST service. There is no client side validation of arguments. See the
            `following page <https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html>`_
            for details on how searching works in the UI and how to craft a query for the API.

        Examples
        --------
            Using the search class method::

                # Query strings from the AutoFocus web UI
                # https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html
                try:
                    for session in AFSession.search({'field':'session.malware', 'value':1, 'operator':'is'}):
                        pass # Do something with the session
                except AFServerError:
                    pass # Something happened to the server
                except AFClientError:
                    pass # The client did something stupid, likely a bad query was passed

                # Python dictionary with the query parameters
                try:
                    session = AFSession.search({'field':'session.malware', 'value':1, 'operator':'is'}).next()
                except StopIteration:
                    pass # No results found
                except AFServerError:
                    pass # Something happened to the server
                except AFClientError:
                    pass # The client did something stupid, likely a bad query was passed
        Args:
            query str:The query to run against autofocus (will also take dicts per examples)
            sort_by Optional[str]: The field to sort results by
            sort_order Optional[str]; asc or desc sort order

        Yields:
            AFSession: sample objects as they are paged from the REST service

        Raises
        ------
            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected

        """
        for res in AFSessionFactory.search(query, sort_by, sort_order):
            yield res

class AFSessionFactory(AutoFocusAPI):
    """
    AFSessionFactory is a class to handle fetching an instantiating AFSession objects. See AFSession for details
    """

    @classmethod
    def count(cls, query):
        """
        Notes: See AFSession.count documentation
        """

        return cls._api_count("/sessions/search", query, None)

    @classmethod
    def scan(cls, query, page_size):
        """
        Notes: See AFSession.scan documentation
        """

        for res in cls._api_scan("/sessions/search", query, None, page_size):
            yield AFSession(**res['_source'])

    @classmethod
    def search(cls, query, sort_by, sort_order):
        """
        Notes: See AFSession.search documentation
        """

        for res in cls._api_search("/sessions/search", query, None, sort_by, sort_order):
            yield AFSession(**res['_source'])

class AFSampleFactory(AutoFocusAPI):
    """
    AFSampleFactory is a class to handle fetching an instantiating AFSample objects. See AFSample for details
    """

    @classmethod
    def search(cls, query, scope, sort_by, sort_order):
        """
        Notes: See AFSample.search documentation
        """

        for res in cls._api_search("/samples/search", query, scope, sort_by, sort_order):
            try:
                yield AFSample(**res['_source'])
            except AutoFocusException as e:
                raise e
            except Exception as e:
                # HMMM bug in sample data
                pass

    @classmethod
    def count(cls, query, scope):
        """
        Notes: See AFSample.count documentation
        """

        return cls._api_count("/samples/search", query, scope)

    @classmethod
    def scan(cls, query, scope, page_size):
        """
        Notes: See AFSample.scan documentation
        """

        for res in cls._api_scan("/samples/search", query, scope, page_size):
            yield AFSample(**res['_source'])

    @classmethod
    def get(cls, hash):
        """
        Notes: See AFSample.get documentation
        """

        if not re.match(r'^([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$', hash):
            raise AFClientError("Argument mush be a valid md5, sha1, or sha256 hash")

        res = None

        query = { "operator" : "is", "value" : hash }

        try:
            if len(hash) == 32:
                query['field'] = "sample.md5"
            elif len(hash) == 40:
                query['field'] = "sample.sha1"
            elif len(hash) == 64:
                query['field'] = "sample.sha256"

            res = AFSample.search(query).next()

        except StopIteration:
            pass

        if not res:
            raise AFSampleAbsent("No such hash found in AutoFocus")

        return res

class AFSample(AutoFocusObject):

    def __init__(self, **kwargs):
        """
        The AFSample should be treated as read-only object matching data found in the AutoFocus REST API. It should NOT
        be instantiated directly. Instead, call the various class method factories to get instance(s) of AFSample. See:
        - :func:`AFSample.search`
        - :func:`AFSample.get`
        """

        known_attributes = ("create_date", "filetype", "malware", "md5", "sha1", "sha256", "size", "multiscanner_hit",\
                            "virustotal_hit", "source_label", "finish_date", "tag", "digital_signer", "update_date",\
                            "ssdeep", "imphash", "ispublic")

        # TODO: remove this when the library matures, needless checking once we sort out attributes
        for k, v in kwargs.items():
            if k not in known_attributes:
                pass
                #sys.stderr.write("Unknown attribute for sample returned by REST service, please tell BSmall about this - %s:%s" % (k, v))

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

        #:Optional[bool]: whether the sample is public or not. If is unknown, it will be None
        self.is_public = kwargs.get("ispublic", None)
        if self.is_public:
            self.is_public = True
        elif self.is_public is not None:
            self.is_public = False

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

        #Below are our verdict predefined meaning:
        # benign : 0
        # malware : 1
        # grayware: 2
        # pending : -100, sample record exists in DB , but no value in malware field (internally, sample is at pending state or at error state, but less than configurable 1 day old)
        # error : -101, sample in error state (internally, sample is at error state, more than 1 day old)
        # unknown : -102, cannot find sample record in DB
        wf_verdict_map = {
            0: "benign",
            1: "malware",
            2: "grayware",
            -100: "pending",
            -101: "error",
            -102: "unknown"
        }

        #: Optional[str]: The verdict of the sample as a string. Will be None if the sample doesn't have a verdict
        self.verdict = None

        if kwargs.get('malware', None) in wf_verdict_map:
            self.verdict = wf_verdict_map[kwargs['malware']]

        #: bool: Whether WildFire thinks the sample is benign or not
        self.benign = True if kwargs.get('malware', None) == 0 else False

        #: bool: Whether WildFire thinks the sample is grayware or not
        self.grayware = True if kwargs.get('malware', None) == 2 else False

        #: bool: Whether WildFire thinks the sample is Malware or not
        self.malware = True if kwargs.get('malware', None) == 1 else False

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
        self._tags = kwargs.get('tag', [])

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

    @classmethod
    def count(cls, query, scope = "global"):
        """

        The AFSample.count method returns the total number of samples matching the query for the given scope

        Notes
        -----

            Argument validation is done via the REST service. There is no client side validation of arguments. See the
            `following page <https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html>`_
            for details on how searching works in the UI and how to craft a query for the API.

        Examples
        --------
            Using the count class method::

                # Query strings from the AutoFocus web UI
                # https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html
                try:
                    total_sample_count = AFSample.count({'field':'sample.malware', 'value':1, 'operator':'is'})
                except AFServerError:
                    pass # Something happened to the server
                except AFClientError:
                    pass # The client did something stupid, likely a bad query was passed

                # Python dictionary with the query parameters
                try:
                    total_sample_count = AFSample.count({'field':'sample.malware', 'value':1, 'operator':'is'})
                except StopIteration:
                    pass # No results found
                except AFServerError:
                    pass # Something happened to the server
                except AFClientError:
                    pass # The client did something stupid, likely a bad query was passed
        Args:
            query str:The query to run against autofocus (will also take dicts per examples)
            scope Optional[str]:The scope of the search you're running. Defaults to "global"

        Returns:
            int: the number of samples matching the query & scope

        Raises
        ------

            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected

        """
        return AFSampleFactory.count(query, scope)

    @classmethod
    def scan(cls, query, scope = "global", page_size = 20000):
        """

        The AFSample.scan method is a factory to return AFSample object instances. These correspond to values returned
        by the query supplied.

        Notes
        -----
            This method is identical to the search method, except it allows for returning results beyond the 4000
            match limit imposed on search. This method does not allow for sorting and can potentially return extremely
            large result sets.

            Argument validation is done via the REST service. There is no client side validation of arguments. See the
            `following page <https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html>`_
            for details on how searching works in the UI and how to craft a query for the API.

        Examples
        --------
            Using the scan class method::

                # Query strings from the AutoFocus web UI
                # https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html
                try:
                    for sample in AFSample.scan({'field':'sample.malware', 'value':1, 'operator':'is'}):
                        pass # Do something with the sample
                except AFServerError:
                    pass # Something happened to the server
                except AFClientError:
                    pass # The client did something stupid, likely a bad query was passed

                # Python dictionary with the query parameters
                try:
                    sample = AFSample.scan({'field':'sample.malware', 'value':1, 'operator':'is'}).next()
                except StopIteration:
                    pass # No results found
                except AFServerError:
                    pass # Something happened to the server
                except AFClientError:
                    pass # The client did something stupid, likely a bad query was passed
        Args:
            query str:The query to run against autofocus (will also take dicts per examples)
            scope Optional[str]:The scope of the search you're running. Defaults to "global"

        Yields:
            AFSample: sample objects as they are paged from the REST service

        Raises
        ------

            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected

        """
        for sample in AFSampleFactory.scan(query, scope, page_size):
            yield sample

    @classmethod
    def search(cls, query, scope = "global", sort_by = "create_date", sort_order = "asc"):
        """

        The AFSample.search method is a factory to return AFSample object instances. These correspond to values returned
        by the query supplied.

        Notes
        -----
            This method has a hard 4000 result limit imposed by the REST API.

            Argument validation is done via the REST service. There is no client side validation of arguments. See the
            `following page <https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html>`_
            for details on how searching works in the UI and how to craft a query for the API.

        Examples
        --------
            Using the search class method::

                # Query strings from the AutoFocus web UI
                # https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html
                try:
                    for sample in AFSample.search({'field':'sample.malware', 'value':1, 'operator':'is'}):
                        pass # Do something with the sample
                except AFServerError:
                    pass # Something happened to the server
                except AFClientError:
                    pass # The client did something stupid, likely a bad query was passed

                # Python dictionary with the query parameters
                try:
                    sample = AFSample.search({'field':'sample.malware', 'value':1, 'operator':'is'}).next()
                except StopIteration:
                    pass # No results found
                except AFServerError:
                    pass # Something happened to the server
                except AFClientError:
                    pass # The client did something stupid, likely a bad query was passed
        Args:
            query str:The query to run against autofocus (will also take dicts per examples)
            scope Optional[str]:The scope of the search you're running. Defaults to "global"
            sort_by Optional[str]: The field to sort results by
            sort_order Optional[str]; asc or desc sort order

        Yields:
            AFSample: sample objects as they are paged from the REST service

        Raises
        ------

            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected

        """
        for sample in AFSampleFactory.search(query, scope, sort_by, sort_order):
            yield sample

    # TODO: Convenience method to handle searching multiple hashes (do crazy paging to get more than 100 or 10000)
    @classmethod
    def _search_hashes(cls, hashes):
        raise NotImplemented

    @classmethod
    def get(cls, hash):
        """
        Args:
            hash (str): either a md5, sha1, or sha256 hash of the sample needed

        Returns:
            AFSample: Instance of AFSample that matches the hash offered

        Raises:
            AFClientError: In the case that the client did something unexpected or an invalid hash was offered
            AFServerError: In the case that the client did something unexpected
            AFSampleAbsent in the case that the sample is absent in autofocus

        Examples
        --------
            Examples using the get method::

                try:
                    sample = AFSample.get("31a9133e095632a09a46b50f15b536dd2dc9e25e7e6981dae5913c5c8d75ce20")
                    sample = AFSample.get("97a174dbc51a2c4f9cad05b6fc9af10d3ba7c919")
                    sample = AFSample.get("a1f19a3ebd9213d2f0d895ec86a53390")
                except AFSampleAbsent:
                    pass # Sample didn't exist

        """
        return AFSampleFactory.get(hash)

    def get_activity(self, sections, platforms):
        """
        Notes:
            Points to :func:`AFSample.get_analyses`. See documentation there for details.
        """
        return self.get_analyses(sections, platforms)

    def get_analyses(self, sections = None, platforms = None):
        """
        Args:
            sections (Optional[array[str]]): The analysis sections desired. Can also be class objects for the
                desired sections. Defaults to all possible sections.
            platforms (Optional[array[str]]): The analysis platforms desired. Defaults to all possible platforms.

        Returns:
            array[AutoFocusAnalysis]: A list of AutoFocusAnalysis sub-class instances representing the analysis

        Raises:
            AFClientError: In the case that the client did something unexpected
            AFServerError: In the case that the client did something unexpected

        Notes:
            sections can also be a string or AutoFocusAnalysis subclass
        """

        mapped_sections = []

        if not sections:
            sections = ALL_ANALYSIS_SECTIONS

        if not (type(sections) is list or type(sections) is tuple):
            sections = [sections]

        for section in sections:
            if type(section) is not str:
                mapped_sections.append(_class_analysis_map[section])
            else:
                mapped_sections.append(section)

        resp_data = AutoFocusAPI._api_request(
            "/sample/" + self.sha256 + "/analysis", \
            post_data = { "sections" : mapped_sections, "platforms" : platforms }).json()

        analyses = []

        for section in resp_data['sections']:
            af_analysis_class = _analysis_class_map.get(section, None)

            if not af_analysis_class:
                raise AFClientError("Was expecting a known section in analysis_class_map, got {} instead"
                                    .format(section))

            #            for platform in resp_data['platforms']: # staticAnlyzer is being returned by isn't in the set?
            for platform in resp_data[section].keys():
                for data in resp_data[section][platform]:
                    # TODO: remove try catch when all analyses types are normalized
                    try:
                        analyses.append(af_analysis_class._parse_auto_focus_response(platform, data))
                        # Adding the _raw_line for potential debug use later, can be removed
                        analyses[-1]._raw_line = data['line']
                    except _InvalidAnalysisData:
                        pass
                    except:
                        pass

        return analyses

class AutoFocusAnalysis(AutoFocusObject):

    def __init__(self, obj_data):
        for k,v in obj_data.items():
            setattr(self, k, v)

    @classmethod
    def _parse_auto_focus_response(cls, platform, resp_data):
        return cls(resp_data)

#apk_defined_activity
class AFApkActivityAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, activity, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the activity observered
        self.activity = activity

    @classmethod
    def _parse_auto_focus_response(cls, platform, activity_data):

        line_parts = activity_data['line'].split(" , ")
        (activity) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (activity_data.get('b', 0), activity_data.get('m', 0), activity_data.get('g', 0))
        return cls(platform, activity, benign_c, malware_c, grayware_c)

#apk_defined_intent_filter
class AFApkIntentFilterAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, intent, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the intent observered
        self.intent = intent

    @classmethod
    def _parse_auto_focus_response(cls, platform, intent_data):

        line_parts = intent_data['line'].split(" , ")
        (intent) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (intent_data.get('b', 0), intent_data.get('m', 0), intent_data.get('g', 0))
        return cls(platform, intent, benign_c, malware_c, grayware_c)

#apk_defined_receiver
class AFApkReceiverAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, receiver, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the receiver used
        self.receiver = receiver

    @classmethod
    def _parse_auto_focus_response(cls, platform, rcv_data):

        line_parts = rcv_data['line'].split(" , ")
        (receiver) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (rcv_data.get('b', 0), rcv_data.get('m', 0), rcv_data.get('g', 0))
        return cls(platform, receiver, benign_c, malware_c, grayware_c)

#apk_defined_sensor
class AFApkSensorAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, sensor, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the sensor used
        self.sensor = sensor

    @classmethod
    def _parse_auto_focus_response(cls, platform, sensor_data):

        line_parts = sensor_data['line'].split(" , ")
        (sensor) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (sensor_data.get('b', 0), sensor_data.get('m', 0), sensor_data.get('g', 0))
        return cls(platform, sensor, benign_c, malware_c, grayware_c)

#apk_defined_service
class AFApkServiceAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, service, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the service used
        self.service = service

    @classmethod
    def _parse_auto_focus_response(cls, platform, svc_data):

        line_parts = svc_data['line'].split(" , ")
        (service) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (svc_data.get('b', 0), svc_data.get('m', 0), svc_data.get('g', 0))
        return cls(platform, service, benign_c, malware_c, grayware_c)

#apk_embeded_url
class AFApkEmbededUrlAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, url, disasm_file_path, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The URL accessed by the device
        self.url = url

        #: str: the dissasembled file path
        self._disasm_file_path = disasm_file_path

    @classmethod
    def _parse_auto_focus_response(cls, platform, perm_data):

        line_parts = perm_data['line'].split(" , ")
        (url, disasm_file_path) = line_parts[0:2]
        (benign_c, malware_c, grayware_c) = (perm_data.get('b', 0), perm_data.get('m', 0), perm_data.get('g', 0))
        return cls(platform, url, disasm_file_path, benign_c, malware_c, grayware_c)

#apk_requested_permission
class AFApkRequestedPermissionAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, permission, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing the permission requested  by the sample
        self.permission = permission

    @classmethod
    def _parse_auto_focus_response(cls, platform, perm_data):

        line_parts = perm_data['line'].split(" , ")
        (permission) = line_parts[0]
        (benign_c, malware_c, grayware_c) = (perm_data.get('b', 0), perm_data.get('m', 0), perm_data.get('g', 0))
        return cls(platform, permission, benign_c, malware_c, grayware_c)

#apk_sensitive_api_call
class AFApkSensitiveApiCallAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, class_, method, disasm_file_path, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The name of the class accessed by the APK
        self.class_name = class_

        #: str: The name of the method accessed by the APK
        self.method = method

        #: Optional(str): the dissasembled file path
        self._disasm_file_path = disasm_file_path

    @classmethod
    def _parse_auto_focus_response(cls, platform, api_data):

        line_parts = api_data['line'].split(" , ")
        (class_, method) = line_parts[0].split(";->")
        class_ = class_.replace("/", ".")
        disasm_file_path = None
        if len(line_parts) > 1:
            disasm_file_path = line_parts[1]
        (benign_c, malware_c, grayware_c) = (api_data.get('b', 0), api_data.get('m', 0), api_data.get('g', 0))
        return cls(platform, class_, method, disasm_file_path, benign_c, malware_c, grayware_c)

#apk_suspicious_api_call
class AFApkSuspiciousApiCallAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, class_, method, disasm_file_path, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The name of the class accessed by the APK
        self.class_name = class_

        #: str: The name of the method accessed by the APK
        self.method = method

        #: Optional(str): the dissasembled file path
        self._disasm_file_path = disasm_file_path

    @classmethod
    def _parse_auto_focus_response(cls, platform, api_data):

        line_parts = api_data['line'].split(" , ")
        (class_, method) = line_parts[0].split(";->")
        class_ = class_.replace("/", ".")
        disasm_file_path = None
        if len(line_parts) > 1:
            disasm_file_path = line_parts[1]
        (benign_c, malware_c, grayware_c) = (api_data.get('b', 0), api_data.get('m', 0), api_data.get('g', 0))
        return cls(platform, class_, method, disasm_file_path, benign_c, malware_c, grayware_c)

#apk_suspicious_file
class AFApkSuspiciousFileAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, file_path, file_type, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The path to the file on the file system
        self.file_path = file_path

        #: str: the type of file that was identified
        self.file_type = file_type

    @classmethod
    def _parse_auto_focus_response(cls, platform, file_data):

        line_parts = file_data['line'].split(" , ")
        (file_path, file_type) = line_parts[0:2]
        (benign_c, malware_c, grayware_c) = (file_data.get('b', 0), file_data.get('m', 0), file_data.get('g', 0))
        return cls(platform, file_path, file_type, benign_c, malware_c, grayware_c)

#apk_suspicious_string
class AFApkSuspiciousStringAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, string, file_name, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: The string that was identified as suspicious
        self.string = string

        #: str: The name of the file the suspicious string was found in
        self.file_name = file_name

    @classmethod
    def _parse_auto_focus_response(cls, platform, string_data):

        line_parts = string_data['line'].split(" , ")
        (string, file_name) = line_parts[0:2]
        (benign_c, malware_c, grayware_c) = (string_data.get('b', 0), string_data.get('m', 0), string_data.get('g', 0))
        return cls(platform, string, file_name, benign_c, malware_c, grayware_c)

#behavior_type
class AFBehaviorTypeAnalysis(AutoFocusAnalysis):

    def __init__(self, platform, behavior):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: str: A string representing a behavior the sample exhibits
        self.behavior = behavior

    @classmethod
    def _parse_auto_focus_response(cls, platform, conn_data):

        ba = cls(platform, conn_data['line'])

        return ba

#connection
class AFConnectionActivity(AutoFocusAnalysis):

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


    """
    Normalizing connection analysis is a nightmare. There are multiple formats you can expect:
     - <protocol>-connection , <dst_ip>:<dst_port> , <unknown_field> , <country_code>
     - <protocol>-connection , <dst_ip>:<dst_port> , <unknown_field>
     - bind , <unknown integer>
     - connect , <dst_ip>:<dst_port> , <unknown_field> , <country_code>
     - <protocol> , <dst_ip>:<dst_port> , <country_code>
     - <protocol>-listening , <src_port>
     - <protocol>-listening , <ApiFunctionName> , <src_port>
     - <process name>, <proto>-listening, RecvFrom, <Integer>
     - <process name>, <proto>-listening, Recv, <Integer>
    """
    @classmethod
    def _parse_auto_focus_response(cls, platform, conn_data):

        (dst_ip, src_port, dst_port, uk2, country_code) = (None, None, None, None, None)
        line_parts = conn_data['line'].split(" , ")

        if len(line_parts) >= 4:

            if "Recv" in line_parts and [v for v in line_parts if "-listening" in v]:
                raise _InvalidAnalysisData

            if len(line_parts) > 4:
                (process_name, protocol, dst_ip_port, uk2, country_code) = line_parts[0:5]
            else:
                (process_name, protocol, dst_ip_port, country_code) = line_parts[0:4]
            (dst_ip, dst_port) = dst_ip_port.split(":")
        elif len(line_parts) == 3:
            (process_name, protocol, src_port) = line_parts[0:3]

            if protocol == "bind":
                raise _InvalidAnalysisData()

        if protocol == "connect":
            protocol = "tcp"

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        if country_code == "" or country_code == "N/A":
            country_code = None

        (benign_c, malware_c, grayware_c) = (conn_data.get('b', 0), conn_data.get('m', 0), conn_data.get('g', 0))

        action = "connect"
        if protocol and "-" in protocol:
            (protocol, action) = protocol.split("-")

            if action == "connection":
                action = "connect"
            elif action == "listening":
                action = 'listen'
            else:
                pass
                #TODO remove this and throw an exception when we are confident about our normalization
                #sys.stderr.write("Unknown connection action {} -- tell BSMALL\n".format(action))

        if protocol:
            protocol = protocol.lower()

        #TODO remove this and throw an exception when we are confident about our normalization
        if protocol and protocol not in ('tcp', 'udp', 'icmp', 'gre'):
            pass
            #sys.stderr.write("Unknown protocol {} -- tell BSMALL\n".format(protocol))

        ca = cls(platform, process_name, src_port, dst_ip, dst_port, protocol, action, country_code, benign_c, \
                 malware_c, grayware_c)

        return ca

#dns
class AFDnsActivity(AutoFocusAnalysis):

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
    def _parse_auto_focus_response(cls, platform, dns_data):

        line_parts = dns_data['line'].split(" , ")
        (query, response, type) = line_parts[0:3]
        (benign_c, malware_c, grayware_c) = (dns_data.get('b', 0), dns_data.get('m', 0), dns_data.get('g', 0))

        da = cls(platform,query, response, type, benign_c, malware_c, grayware_c)

        return da

#file
class AFFileActivity(AutoFocusAnalysis):

    def __init__(self, platform, process_name, file_action, file_name, benign, malware, grayware):
        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional[str]: The name of the process affecting the file
        self.process_name = process_name

        #: str: The attempted action taken on a file
        self.file_action = file_action

        #: Optional[str]: The affected file's name
        self.file_name = file_name

    @classmethod
    def _parse_auto_focus_response(cls, platform, file_data):

        line_parts = file_data['line'].split(" , ")
        if len(line_parts) < 3:
            (process_name, file_action) = line_parts[0:2]
            file_name = None
        else:
            (process_name, file_action, file_name) = line_parts[0:3]
        (benign_c, malware_c, grayware_c) = (file_data.get('b', 0), file_data.get('m', 0), file_data.get('g', 0))

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        fa = cls(platform, process_name, file_action, file_name, benign_c, malware_c, grayware_c)

        return fa

#http
class AFHttpActivity(AutoFocusAnalysis):

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
    def _parse_auto_focus_response(cls, platform, http_data):

        line_parts = http_data['line'].split(" , ", 3)
        (host, method, url, user_agent) = line_parts[0:4]
        (benign_c, malware_c, grayware_c) = (http_data.get('b', 0), http_data.get('m', 0), http_data.get('g', 0))

        ha = cls(platform,host, method, url, user_agent, benign_c, malware_c, grayware_c)

        return ha

#japi
class AFJavaApiActivity(AutoFocusAnalysis):

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
    def _parse_auto_focus_response(cls, platform, japi_data):

        (benign_c, malware_c, grayware_c) = (japi_data.get('b', 0), japi_data.get('m', 0), japi_data.get('g', 0))

        ja = cls(platform, japi_data['line'], benign_c, malware_c, grayware_c)

        return ja

#mutex
class AFMutexActivity(AutoFocusAnalysis):

    def __init__(self, platform, process_name, function_name, mutex_name, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional[str]: The name of the process affecting the mutex
        self.process_name = process_name

        #: str: The function called to affect the mutex (At the time of this writing, have only seen CreateMutexW)
        self.function_name = function_name

        #: str: THe name of the mutex affected
        self.mutex_name = mutex_name


    @classmethod
    def _parse_auto_focus_response(cls, platform, mutex_data):

        (process_name, function_name, mutex_name) = mutex_data['line'].split(" , ")
        (benign_c, malware_c, grayware_c) = (mutex_data.get('b', 0), mutex_data.get('m', 0), mutex_data.get('g', 0))

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        ma = cls(platform, process_name, function_name, mutex_name, benign_c, malware_c, grayware_c)

        return ma

#misc
class AFApiActivity(AutoFocusAnalysis):

    def __init__(self, platform, process_name, function_name, function_arguments, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional[str]: The name of the process affecting the mutex
        self.process_name = process_name

        #: str: The function called
        self.function_name = function_name

        #: array[str]: arguments passed to the function
        self.function_arguments = function_arguments


    @classmethod
    def _parse_auto_focus_response(cls, platform, misc_data):

        if not misc_data['line']:
            raise _InvalidAnalysisData()

        line_parts =  misc_data['line'].split(" , ")
        (process_name, function_name) = line_parts[0:2]
        func_args = line_parts[2:]
        (benign_c, malware_c, grayware_c) = (misc_data.get('b', 0), misc_data.get('m', 0), misc_data.get('g', 0))

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        ma = cls(platform, process_name, function_name, func_args, benign_c, malware_c, grayware_c)

        return ma

#process
class AFProcessActivity(AutoFocusAnalysis):

    def __init__(self, platform, process_name, action, parameters, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional(str): The name of the process affecting the process
        self.process_name = process_name

        #: str: The function name called or the action affecting the parameters
        self.action = action

        #: array[str]: arguments passed to the function
        self.parameters = parameters


    @classmethod
    def _parse_auto_focus_response(cls, platform, misc_data):

        line_parts =  misc_data['line'].split(" , ")
        (process_name, action) = line_parts[0:2]
        parameters = line_parts[2:]
        (benign_c, malware_c, grayware_c) = (misc_data.get('b', 0), misc_data.get('m', 0), misc_data.get('g', 0))

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        ma = cls(platform, process_name, action, parameters, benign_c, malware_c, grayware_c)

        return ma

#registry
class AFRegistryActivity(AutoFocusAnalysis):

    def __init__(self, platform, process_name, action, registry_key, parameters, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional(str): The name of the process affecting the registry
        self.process_name = process_name

        #: str: The function name called or the action affecting the parameters
        self.action = action

        #: str: The registry key being affected
        self.registry_key = registry_key

        #: array[str]: arguments passed to the function
        self.parameters = parameters


    @classmethod
    def _parse_auto_focus_response(cls, platform, registry_data):

        line_parts =  registry_data['line'].split(" , ")
        (process_name, action) = line_parts[0:2]

        if len(line_parts) < 3:
            raise _InvalidAnalysisData()

        registry_key = line_parts[2]
        parameters = line_parts[2:]
        (benign_c, malware_c, grayware_c) = (registry_data.get('b', 0), registry_data.get('m', 0), registry_data.get('g', 0))

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        ma = cls(platform, process_name, action, registry_key, parameters, benign_c, malware_c, grayware_c)

        return ma

#service
class AFServiceActivity(AutoFocusAnalysis):

    def __init__(self, platform, process_name, action, parameters, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: Optional(str): The name of the process affecting the service
        self.process_name = process_name

        #: str: The function name called or the action affecting the parameters
        self.action = action

        #: array[str]: arguments passed to the function
        self.parameters = parameters


    @classmethod
    def _parse_auto_focus_response(cls, platform, service_data):

        line_parts =  service_data['line'].split(" , ")
        (process_name, action) = line_parts[0:2]
        parameters = line_parts[2:]
        (benign_c, malware_c, grayware_c) = (service_data.get('b', 0), service_data.get('m', 0), service_data.get('g', 0))

        if not process_name or process_name.lower() in (" ", "unknown"):
            process_name = None

        ma = cls(platform, process_name, action, parameters, benign_c, malware_c, grayware_c)

        return ma

#user_agent
class AFUserAgentFragment(AutoFocusAnalysis):

    def __init__(self, platform, fragment, benign, malware, grayware):

        #: str: The platform the sample analysis is from
        self.platform = platform

        #: int: The number of samples regarded as benign related to this analysis
        self.benign_count = int(benign)

        #: int: The number of samples regarded as malware related to this analysis
        self.malware_count = int(malware)

        #: int: The number of samples regarded as grayware related to this analysis
        self.grayware_count = int(grayware)

        #: str: A string representing a fragment of the user agent (stripping fluff, ie "Mozilla/5.0")
        self.fragment = fragment

    @classmethod
    def _parse_auto_focus_response(cls, platform, ua_data):

        (benign_c, malware_c, grayware_c) = (ua_data.get('b', 0), ua_data.get('m', 0), ua_data.get('g', 0))

        ba = cls(platform, ua_data['line'], benign_c, malware_c, grayware_c)

        return ba

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
_analysis_class_map['connection'] = AFConnectionActivity
_analysis_class_map['dns'] = AFDnsActivity
_analysis_class_map['file'] = AFFileActivity
_analysis_class_map['http'] = AFHttpActivity
_analysis_class_map['japi'] = AFJavaApiActivity
_analysis_class_map['mutex'] = AFMutexActivity
_analysis_class_map['misc'] = AFApiActivity
_analysis_class_map['process'] = AFProcessActivity
_analysis_class_map['registry'] = AFRegistryActivity
_analysis_class_map['service'] = AFServiceActivity
_analysis_class_map['user_agent'] = AFUserAgentFragment

for k,v in _analysis_class_map.items():
    _class_analysis_map[v] = k
    v.__autofocus_section = k

if __name__ == "__main__":
    pass

