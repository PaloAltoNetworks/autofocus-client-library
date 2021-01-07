from datetime import datetime
from .base import AutoFocusObject


class Whois(AutoFocusObject):
    def __init__(self, kwargs):

        #: str: country information
        self.admin_country = kwargs.get("whoisAdminCountry")

        #: str: admin email
        self.admin_email = kwargs.get("whoisAdminEmail")

        # str: name of admin
        self.admin_name = kwargs.get("whoisAdminName")
        created = kwargs.get("whoisDomainCreationDate")

        #: datetime: when domain was created
        self.domain_creation_date = datetime.strptime(created, "%Y-%m-%d") if created else None
        expiration = kwargs.get("whoisDomainExpireDate")

        #: datetime: when domain expires
        self.domain_expiration_date = datetime.strptime(expiration, "%Y-%m-%d") if expiration else None
        updated = kwargs.get("whoisDomainUpdateDate")

        #: datetime: when domain was updated
        self.domain_updated_date = datetime.strptime(updated, "%Y-%m-%d") if updated else None

        #: str: registrar for domain
        self.registrar = kwargs.get("whoisRegistrar")

        #: str: registrar url
        self.registrar_url = kwargs.get("whoisRegistrarUrl")

        #: str: registrant
        self.registrant = kwargs.get("whoisRegistrant")


class ThreatIntelCard(AutoFocusObject):
    def __init__(self, kwargs):

        _first_seen_ts = kwargs.get("firstSeenTsGlobal")
        #: datetime: when indicator was first seen
        self.first_seen = datetime.fromtimestamp(_first_seen_ts / 1000) if _first_seen_ts else None

        _last_seen_ts = kwargs.get("lastSeenTsGlobal")
        #: datetime: when indicator was last seen
        self.last_seen = datetime.fromtimestamp(_last_seen_ts / 1000) if _last_seen_ts else None

        #: List[str]: which data sources saw indicator
        self.seen_by = kwargs.get("seenByDataSourceIds")

        verdicts = kwargs.get("latestPanVerdicts")
        wildfire_verdict = verdicts.get("WF_SAMPLE")
        pandb_verdict = verdicts.get("PAN_DB")

        #: str: verdict in WF if seen by WF
        self.wildfire_verdict = wildfire_verdict.lower() if wildfire_verdict else None

        #: str: verdict in PanDB if seen by PanDB
        self.pandb_verdict = pandb_verdict.lower() if pandb_verdict else None

        # Whois: whois information if available
        self.whois = Whois(kwargs)
