from datetime import datetime
from .base import AutoFocusObject

# A dictionaries for mapping AutoFocus Analysis Response objects
# to their corresponding normalization classes and vice-vers
_coverage_2_class_map = {}
_class_2_coverage_map = {}


class AutoFocusCoverage(AutoFocusObject):

    def __init__(self, obj_data):
        for k, v in list(obj_data.items()):
            setattr(self, k, v)

    @classmethod
    def _parse_auto_focus_response(cls, platform, resp_data):
        return cls(resp_data)


class URLCatogorization(AutoFocusCoverage):

    """ The catagorization of a URL that's involved with a sample """

    def __init__(self, kwargs):

        #: str: The url
        self.url = kwargs.get("url")

        #: str: The category for the URL
        self.category = kwargs.get("cat").rstrip()

        #: int: An importance rating
        self.importance = kwargs.get("importance")


class C2DomainSignature(AutoFocusCoverage):

    """ Domain Signature detecting C2 Activity """

    def __init__(self, kwargs):

        #: str: The domain related to this signature
        self.domain = kwargs.get("domain")

        #: str: The name of the signature
        self.name = kwargs.get("name")

        #: datetime: The time the signature was created
        self.time = datetime.strptime(kwargs['create_date'], '%Y-%m-%d %H:%M:%S')

        #: bool: Whether the signature is in the current release
        self.current_daily_release = kwargs.get("currently_present_daily")

        #: bool: Whether the signature is in the current 15 minute release
        self.current_15_minute_release = kwargs.get("currently_present_15min")

        #: bool: Whether the signature is in the current 5 minute release
        self.current_5_minute_release = kwargs.get("currently_present_5min")

        #: int: The first 15 minute release version the signature was included in
        self.first_15_minute_release = kwargs.get("first_added_15min")

        #: int: The first 5 minute release version the signature was included in
        self.first_5_minute_release = kwargs.get("first_added_5min")

        #: int: The first daily release version the signature was included in
        self.first_daily_release = kwargs.get("first_added_daily")

        #: int: The latest 15 minute release version the signature was included in
        self.latest_15_minute_release = kwargs.get("last_added_15min")

        #: int: The latest 5 minute release version the signature was included in
        self.latest_5_minute_release = kwargs.get("last_added_5min")

        #: int: The latest daily release version the signature was included in
        self.latest_daily_release = kwargs.get("last_added_daily")


class AVSignature(AutoFocusCoverage):

    """ AV Signature detection of a sample """

    def __init__(self, kwargs):

        #: str: The name of the signature
        self.name = kwargs.get("name")

        #: datetime: The time the signature was created
        self.time = datetime.strptime(kwargs['create_date'], '%Y-%m-%d %H:%M:%S')

        #: bool: Whether the signature is in the current release
        self.current_daily_release = kwargs.get("currently_present_daily")

        #: bool: Whether the signature is in the current 15 minute release
        self.current_15_minute_release = kwargs.get("currently_present_15min")

        #: bool: Whether the signature is in the current 5 minute release
        self.current_5_minute_release = kwargs.get("currently_present_5min")

        #: int: The first 15 minute release version the signature was included in
        self.first_15_minute_release = kwargs.get("first_added_15min")

        #: int: The first 5 minute release version the signature was included in
        self.first_5_minute_release = kwargs.get("first_added_5min")

        #: int: The first daily release version the signature was included in
        self.first_daily_release = kwargs.get("first_added_daily")

        #: int: The latest 15 minute release version the signature was included in
        self.latest_15_minute_release = kwargs.get("last_added_15min")

        #: int: The latest 5 minute release version the signature was included in
        self.latest_5_minute_release = kwargs.get("last_added_5min")

        #: int: The latest daily release version the signature was included in
        self.latest_daily_release = kwargs.get("last_added_daily")


class DNSDownloadSignature(AutoFocusCoverage):

    """ A DNS signature that detected a domain known to host malicious files """

    def __init__(self, kwargs):

        #: str: The domain related to this signature
        self.domain = kwargs.get("domain")

        #: str: The name of the signature
        self.name = kwargs.get("name")

        #: datetime: The time the signature was created
        self.time = datetime.strptime(kwargs['create_date'], '%Y-%m-%d %H:%M:%S')

        #: bool: Whether the signature is in the current release
        self.current_daily_release = kwargs.get("currently_present_daily")

        #: bool: Whether the signature is in the current 15 minute release
        self.current_15_minute_release = kwargs.get("currently_present_15min")

        #: bool: Whether the signature is in the current 5 minute release
        self.current_5_minute_release = kwargs.get("currently_present_5min")

        #: int: The first 15 minute release version the signature was included in
        self.first_15_minute_release = kwargs.get("first_added_15min")

        #: int: The first 5 minute release version the signature was included in
        self.first_5_minute_release = kwargs.get("first_added_5min")

        #: int: The first daily release version the signature was included in
        self.first_daily_release = kwargs.get("first_added_daily")

        #: int: The latest 15 minute release version the signature was included in
        self.latest_15_minute_release = kwargs.get("last_added_15min")

        #: int: The latest 5 minute release version the signature was included in
        self.latest_5_minute_release = kwargs.get("last_added_5min")

        #: int: The latest daily release version the signature was included in
        self.latest_daily_release = kwargs.get("last_added_daily")


_coverage_2_class_map['dns_sig'] = C2DomainSignature
_coverage_2_class_map['url_cat'] = URLCatogorization
_coverage_2_class_map['wf_av_sig'] = AVSignature
_coverage_2_class_map['fileurl_sig'] = DNSDownloadSignature

for k, v in list(_coverage_2_class_map.items()):
    _class_2_coverage_map[v] = k
    v.__autofocus_section = k
