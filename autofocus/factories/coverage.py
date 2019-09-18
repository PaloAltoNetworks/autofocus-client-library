from ..config import get_logger
from .base import AutoFocusAPI
from .base import APIRequest
from ..exceptions import SampleAbsent
from ..exceptions import ClientError


class CoverageFactory(AutoFocusAPI):

    def get_coverage_by_hash(self, sha256):
        """
        Args:
            sha256 (str): The sample's sha256 for the related analyses to pull
            platforms (Optional[array[str]]): The analysis platforms desired. Defaults to all possible platforms.

        Returns:
            array[AutoFocusCoverage]: A list of AutoFocusAnalysis sub-class instances representing the analysis

        Raises:
            ClientError: In the case that the client did something unexpected
            ServerError: In the case that the client did something unexpected
        """
        from ..models.coverage import _coverage_2_class_map

        post_data = {'sections': ["coverage"], "coverage": "true"}

        def _parse_response_data(resp_data):
            coverages = []

            for cov_cat, cov_rows in list(resp_data.get("coverage", {}).items()):

                if cov_cat in ("latest_versions"):
                    continue

                if cov_cat not in _coverage_2_class_map:
                    get_logger().debug("Got section " + cov_cat + ", not found in coverage 2 class map")
                else:
                    for cov_data in cov_rows:
                        try:
                            coverages.append(_coverage_2_class_map[cov_cat](cov_data))
                        except Exception:
                            raise ClientError("Unable to parse responses from server - malformed response?")

            return coverages

        url = "/sample/" + sha256 + "/analysis"

        if not self.async_request:
            try:
                resp = APIRequest(url, post_data=post_data).run()
                return _parse_response_data(resp['json'])
            except ClientError as e:
                if "Requested sample not found" in e.message:
                    raise SampleAbsent("No such sample in AutoFocus")
                raise e

        async def _coro():
            try:
                resp = await APIRequest(url, post_data=post_data, async_request=self.async_request).run()
                return _parse_response_data(resp['json'])
            except ClientError as e:
                if "Requested sample not found" in e.message:
                    raise SampleAbsent("No such sample in AutoFocus")
                raise e
        return _coro()
