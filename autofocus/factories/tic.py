from .base import AutoFocusAPI
from ..exceptions import ClientError


class ThreatIntelFactory(AutoFocusAPI):

    def _parse_response_data(self, resp_data):
        from ..models.tic import ThreatIntelCard
        return ThreatIntelCard(resp_data["json"]["indicator"])

    def _get_tic_card(self, params):
        try:
            resp = self._api_fetch("/tic", params=params)
        except ClientError as e:
            if e.response["status_code"] == 404:
                raise ClientError("Threat Intel Summary card unavailable for sample")
            raise

        return self._parse_response_data(resp)

    def get_tic_summary(self, sha256=None, ipv4=None, ipv6=None, domain=None, url=None, include_tags=True):
        """
        Args:
            sha256 (str): sample sha256 to pull indicator summary for
            ipv4 (str): ipv4 address to pull indicator summary for
            ipv6 (str): ipv6 address to pull indicator summary for
            domain (str): domain to pull indicator summary for
            url (str): url to pull indicator summary for
            include_tags (Optional[bool]): include AF tag data in response (default True)

        Returns:
            ThreatIntelCard: Object containing summary information

        Raises:
            ClientError: In the case that the client did something unexpected
            ServerError: In the case that the server did something unexpected
        """
        params = {
            "includeTags": include_tags
        }

        if not any([sha256, ipv4, ipv6, domain, url]):
            raise ClientError("you must provide one of: sha256, ipv4, ipv6, domain, url")

        if sha256:
            params.update({
                "indicatorType": "FILEHASH",
                "indicatorValue": sha256
            })
        elif ipv4:
            params.update({
                "indicatorType": "ipv4_address",
                "indicatorValue": ipv4
            })
        elif ipv6:
            params.update({
                "indicatorType": "ipv6_address",
                "indicatorValue": ipv6
            })
        elif url:
            params.update({
                "indicatorType": "URL",
                "indicatorValue": url
            })
        elif domain:
            params.update({
                "indicatorType": "DOMAIN",
                "indicatorValue": domain
            })
        else:
            raise NotImplementedError("Unexpected indicator type provided")

        return self._get_tic_card(params)
