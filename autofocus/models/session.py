from datetime import datetime
from .base import AutoFocusObject


class Session(AutoFocusObject):

    def __init__(self, **kwargs):
        """
        The Session should be treated as read-only object matching data found in the AutoFocus REST API. It should NOT
        be instantiated directly. Instead, call the class method factory to get instance(s) of Session. See:
        - :func:`Session.search`
        """

        #: str: The ID for the session
        self.session_id = kwargs.get("session_id")

        #: str: The application this session activity was related to
        self.application = kwargs.get("app")

        #: str: The account name for the device (regular users will only see their account)
        self.account_name = kwargs.get("device_acctname")

        #: str: The country code where the device detecting the activity exists
        self.device_country_code = kwargs.get("device_countrycode")

        #: str: The country where the device detecting the activity exists
        self.device_country = kwargs.get("device_country")

        #: str: The hostname of the device detecting the activity
        self.device_hostname = kwargs.get("device_hostname")

        #: str: The business industry that the activity was detected on
        self.industry = kwargs.get("device_industry")

        #: str: The line of business that the activity was detected on
        self.business_line = kwargs.get("device_lob")

        #: str: The model of the device reporting the activity
        self.device_model = kwargs.get("device_model")

        #: str: The serial number of the device reporting activity
        self.device_serial = kwargs.get("device_serial")

        #: str: The version of the device reporting activity
        self.device_version = kwargs.get("device_swver")

        #: str: The country code of the destination
        self.dst_country_code = kwargs.get("dst_countrycode")

        #: str: The country of the destination
        self.dst_country = kwargs.get("dst_country")

        #: str: The destination IP address
        self.dst_ip = kwargs.get("dst_ip")

        #: bool: true/false whether the IP is private
        self.dst_is_private_ip = True if kwargs.get("dst.isprivateip") else False

        #: int: the destination port of the activity
        self.dst_port = kwargs.get("dst_port")

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
        self.src_country_code = kwargs.get("src_countrycode")

        #: str: The country of the source
        self.src_country = kwargs.get("src_country")

        #: str: The source IP address
        self.src_ip = kwargs.get("src_ip")

        #: bool: true/false whether the IP is private
        self.src_is_private_ip = True if kwargs.get("src_isprivateip") else False

        #: int: the destination port of the activity
        self.src_port = kwargs.get("src_port")

        timestamp = kwargs.get("tstamp")
        self._raw_timestamp = timestamp

        if timestamp:
            timestamp = timestamp.split(".")[0]
            timestamp = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S')

        #: datetime: the time the activity was detected
        self.timestamp = timestamp

        #: str: the user ID the firewall uses if the customer sets up user ID via AD/portal/whatever method they
        #: use - can be used for per user policy enforcement
        self.user_id = kwargs.get("user_id")

        # Doesn't seem to have much meaing. Making private
        self._vsys = kwargs.get("vsys")

        #: str: Where the session data was uploaded from
        self.upload_source = kwargs.get("upload_src")

    @classmethod
    def count(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.session.SessionFactory.count
        """
        from ..factories.session import SessionFactory
        return SessionFactory().count(*args, **kwargs)

    @classmethod
    def scan(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.session.SessionFactory.scan
        """
        from ..factories.session import SessionFactory
        return SessionFactory().scan(*args, **kwargs)

    @classmethod
    def search(cls, *args, **kwargs):
        """
        Notes: This is a proxy method for autofocus.factories.session.SessionFactory.search
        """
        from ..factories.session import SessionFactory
        return SessionFactory().search(*args, **kwargs)
