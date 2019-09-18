from datetime import datetime
from .base import AutoFocusObject
from .base import NotLoaded
from ..exceptions import _InvalidSampleData


class Sample(AutoFocusObject):

    # All known fields. We need to prepopulate attributes with NotLoaded when we are getting a
    # partial modal due to "fields" being offered to the API
    attributes_to_known_fields = {
        "create_date": "create_date",
        "digital_signer": "digital_signer",
        "file_type": "filetype",
        "finish_date": "finish_date",
        "imphash": "imphash",
        "is_public": "ispublic",
        "malware": "malware",
        "benign": "malware",
        "grayware": "malware",
        "verdict": "malware",
        "md5": "md5",
        "multiscanner_hits": "multiscanner_hit",
        "sha1": "sha1",
        "sha256": "sha256",
        "size": "size",
        "source_label": "source_label",
        "ssdeep": "ssdeep",
        "tags": "tag",
        "update_date": "update_date",
        "virustotal_hits": "virustotal_hit",
        "region": "region"
    }

    def __init__(self, **kwargs):
        """
        The Sample should be treated as read-only object matching data found in the AutoFocus REST API. It should NOT
        be instantiated directly. Instead, call the various class method factories to get instance(s) of Sample. See:
        - :func:`Sample.search`
        - :func:`Sample.get`
        """

        if kwargs.get('_limit_attributes_to', []):
            for attribute, field in list(self.__class__.attributes_to_known_fields.items()):
                if attribute not in kwargs['_limit_attributes_to'] and field not in kwargs:
                    kwargs[field] = NotLoaded()

        #: str: sha256 sum of the sample
        self.sha256 = kwargs.get('sha256')

        if not self.sha256:
            raise _InvalidSampleData()

        #: str: md5 sum of the sample
        self.md5 = kwargs.get('md5')

        #: Optional[str]: sha1 sum of the sample
        self.sha1 = kwargs.get('sha1')

        #: Optional[str]: ssdeep sum of the sample
        self.ssdeep = kwargs.get('ssdeep')

        #: Optional[str]: imphash sum of the sample
        self.imphash = kwargs.get('imphash')

        #: Optional[bool]: whether the sample is public or not. If is unknown, it will be None
        self.is_public = kwargs.get("ispublic")
        if type(kwargs.get("ispublic")) is not NotLoaded:
            if self.is_public:
                self.is_public = True
            elif self.is_public is not None:
                self.is_public = False

        #: Optional[str] The file type of the sample
        self.file_type = kwargs.get('filetype')

        kwargs['finish_date'] = kwargs.get('finish_date')
        if kwargs['finish_date'] and type(kwargs['finish_date']) is not NotLoaded:
            kwargs['finish_date'] = datetime.strptime(kwargs['finish_date'], '%Y-%m-%dT%H:%M:%S')

        #: Optional[datetime]: The time the first sample analysis completed
        self.finish_date = kwargs['finish_date']

        kwargs['update_date'] = kwargs.get('update_date')
        if kwargs['update_date'] and type(kwargs['update_date']) is not NotLoaded:
            kwargs['update_date'] = datetime.strptime(kwargs['update_date'], '%Y-%m-%dT%H:%M:%S')

        #: Optional[datetime]: The time the last sample analysis completed
        self.update_date = kwargs['update_date']

        # I don't think this should be optional, but playing it safe for now
        kwargs['create_date'] = kwargs.get('create_date')
        if kwargs['create_date'] and type(kwargs['create_date']) is not NotLoaded:
            kwargs['create_date'] = datetime.strptime(kwargs['create_date'], '%Y-%m-%dT%H:%M:%S')

        #: datetime: The time the sample was first seen by the system
        self.create_date = kwargs['create_date']

        # Below are our verdict predefined meaning:
        # benign : 0
        # malware : 1
        # grayware: 2
        # pending : -100, sample record exists in DB , but no value in malware field (internally,
        #     sample is at pending state or at error state, but less than configurable 1 day old)
        # error : -101, sample in error state (internally, sample is at error state, more than 1 day old)
        # unknown : -102, cannot find sample record in DB
        wf_verdict_map = {
            0: "benign",
            1: "malware",
            2: "grayware",
            4: "phishing",
            -100: "pending",
            -101: "error",
            -102: "unknown"
        }

        #: Optional[str]: The verdict of the sample as a string. Will be None if the sample doesn't have a verdict
        self.verdict = NotLoaded()

        if kwargs.get('malware') in wf_verdict_map:
            self.verdict = wf_verdict_map[kwargs['malware']]

        if type(kwargs.get("malware")) != NotLoaded:
            #: bool: Whether WildFire thinks the sample is benign or not
            self.benign = True if kwargs.get('malware') == 0 else False
            #: bool: Whether WildFire thinks the sample is grayware or not
            self.grayware = True if kwargs.get('malware') == 2 else False
            #: bool: Whether WildFire thinks the sample is Malware or not
            self.malware = True if kwargs.get('malware') == 1 else False
            #: bool: Whether WildFire thinks the sample is phishing or not
            self.phishing = True if kwargs.get('malware') == 4 else False
        else:
            self.benign = NotLoaded()
            self.grayware = NotLoaded()
            self.malware = NotLoaded()
            self.phishing = NotLoaded()

        #: Optional[int]: The size of the sample in bytes
        self.size = kwargs.get('size')

        #: List[Tag]: A list of tags
        self.tags = NotLoaded()

        #: Optional[int]: TODO needs documentation
        self.multiscanner_hits = kwargs.get("multiscanner_hit")

        #: Optiona[int]: how many sources regard the sample to be malicious in Virus Total
        self.virustotal_hits = kwargs.get("virustotal_hit")

        #: Optional[str]: The source the sample came from
        self.source_label = kwargs.get("source_label", "")

        #: Optional[str]: The signer for the sample
        self.digital_signer = kwargs.get("digital_signer")

        # Private _tags
        self._tags = kwargs.get('tag', [])

        # List[str]: list of regions seen in
        self.regions = kwargs.get("region", [])

    def __getattribute__(self, attr):

        from ..models.tag import Tag

        value = object.__getattribute__(self, attr)

        # Tags are offered as strings. Lazy load Tag objects
        # When they are accessed
        if attr == "tags" and type(value) is NotLoaded:

            value = []

            tag_names = getattr(self, "_tags")

            for tag_name in tag_names:
                value.append(Tag.get(tag_name))

            object.__setattr__(self, 'tags', value)

        elif type(value) is NotLoaded:

            new_sample = Sample.get(self.sha256)
            for k, v in list(new_sample.__dict__.items()):
                object.__setattr__(self, k, v)
                if k == attr:
                    value = v if not isinstance(v, NotLoaded) else None

        return value

    @classmethod
    def aggregate(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.sample.SampleFactory.aggregate
        """
        from ..factories.sample import SampleFactory
        return SampleFactory().aggregate(*args, **kwargs)

    @classmethod
    def count(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.sample.SampleFactory.count
        """
        from ..factories.sample import SampleFactory
        return SampleFactory().count(*args, **kwargs)

    @classmethod
    def scan(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.sample.SampleFactory.scan
        """
        from ..factories.sample import SampleFactory
        return SampleFactory().scan(*args, **kwargs)

    @classmethod
    def list(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.sample.SampleFactory.list
        """
        from ..factories.sample import SampleFactory
        return SampleFactory().list(*args, **kwargs)

    @classmethod
    def search(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.sample.SampleFactory.search
        """
        from ..factories.sample import SampleFactory
        return SampleFactory().search(*args, **kwargs)

    @classmethod
    def get(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.sample.SampleFactory.get
        """
        from ..factories.sample import SampleFactory
        return SampleFactory().get(*args, **kwargs)

    def get_activity(self, sections=None, platforms=None):
        """
        Notes:
            Points to :func:`Sample.get_analyses`. See documentation there for details.
        """
        return self.get_analyses(sections, platforms)

    def get_analyses(self, sections=None, platforms=None):
        """
        Notes:
            Calls the :func:`Sample.get_analyses_by_hash` class method with the sample's sha256. See documentation
            there for details.
        """
        from ..factories.analysis import AnalysisFactory
        return AnalysisFactory().get_analyses_by_hash(self.sha256, sections, platforms)

    def get_coverage(self):
        """
        Notes:
            Calls the :func:`Sample.get_analyses_by_hash` class method with the sample's sha256. See documentation
            there for details.
        """
        from ..factories.coverage import CoverageFactory
        return CoverageFactory().get_coverage_by_hash(self.sha256)

    @classmethod
    def get_coverage_by_hash(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.coverage.CoverageFactory.get_coverage_by_hash
        """
        from ..factories.coverage import CoverageFactory
        return CoverageFactory().get_coverage_by_hash(*args, **kwargs)

    @classmethod
    def get_analyses_by_hash(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.analysis.AnalysisFactory.get_analyses_by_hash
        """
        from ..factories.analysis import AnalysisFactory
        return AnalysisFactory().get_analyses_by_hash(*args, **kwargs)
