from ..config import get_logger
from .base import AutoFocusAPI
from .base import APIRequest
from ..exceptions import SampleAbsent
from ..exceptions import ClientError
from ..exceptions import _InvalidAnalysisData

# We're getting some analysis sections back that have useless information in them. Let's create a global
# to track which ones we need skip
_skip_analysis_section = ['info']


class AnalysisFactory(AutoFocusAPI):

    def get_analyses_by_hash(self, sha256, sections=None, platforms=None):
        """
        Args:
            sha256 (str): The sample's sha256 for the related analyses to pull
            sections (Optional[array[str]]): The analysis sections desired. Can also be class objects for the
                desired sections. Defaults to all possible sections.
            platforms (Optional[array[str]]): The analysis platforms desired. Defaults to all possible platforms.

        Returns:
            array[AutoFocusAnalysis]: A list of AutoFocusAnalysis sub-class instances representing the analysis

        Raises:
            ClientError: In the case that the client did something unexpected
            ServerError: In the case that the client did something unexpected

        Notes:
            sections can also be a string or AutoFocusAnalysis subclass
        """
        from ..models.analysis import _class_2_analysis_map
        from ..models.analysis import _analysis_2_class_map
        from ..models.analysis import ApkCertificate

        mapped_sections = []

        post_data = {"platforms": platforms}

        if sections:

            if not (type(sections) is list or type(sections) is tuple):
                sections = [sections]

            for section in sections:
                if type(section) is not str:
                    mapped_sections.append(_class_2_analysis_map[section])
                else:
                    mapped_sections.append(section)

                post_data["sections"] = mapped_sections

        def _parse_resp_data(resp_data):

            analyses = []

            for section in resp_data['sections']:
                af_analysis_class = _analysis_2_class_map.get(section, None)

                if not af_analysis_class:

                    if section in _skip_analysis_section:
                        get_logger().debug(f"Skipping section {section} for {sha256} - in the skip sections lists")
                    # Check to make sure there section is valid data in at least one of the platforms before we warn.
                    # seems we are getting junk sections in responses with no data - need data to care. (list comp)
                    elif section != 'truncated_sections' and [v for v in resp_data[section].values() if v]:
                        get_logger().warning(f"Was expecting a known section in analysis_class_map, got {section}"
                                             f" instead, parsing results for {sha256}")
                    continue

                # for platform in resp_data['platforms']: # staticAnlyzer is being returned by isn't in the set?
                for platform in list(resp_data[section].keys()):
                    for data in resp_data[section][platform]:
                        # TODO: remove try catch when all analyses types are normalized
                        try:
                            analyses.append(af_analysis_class._parse_auto_focus_response(platform, data))
                            # Adding the _raw_line for potential debug use later, can be removed
                            analyses[-1]._raw_line = data['line']

                            if section not in ("apk_cert_file", "apk_certificate_id"):
                                continue

                            # Need to join the two rows for apk_cert_file and apk_cert_id to ApkCertificate
                            analysis_a = analyses[-1]

                            for i in range(0, len(analyses) - 1):
                                analysis_b = analyses[i]
                                if type(analysis_b) is ApkCertificate:
                                    if not analysis_b.sha1:
                                        analysis_b.file_path = analysis_a.file_path
                                        analysis_b.sha1 = analysis_a.sha1
                                        analysis_b.sha256 = analysis_a.sha256
                                        analysis_b.issuer = analysis_a.issuer
                                        analysis_b.owner = analysis_a.owner
                                    analysis_b._raw_line += "\n" + analysis_a._raw_line
                                    analyses.pop()
                                    break

                        except _InvalidAnalysisData as e:
                            get_logger().debug(e)
                        except Exception as e:
                            get_logger().debug(e)

            return analyses

        url = "/sample/" + sha256 + "/analysis"
        if not self.async_request:

            try:
                resp = APIRequest(url, post_data=post_data).run()
                return _parse_resp_data(resp['json'])
            except ClientError as e:
                if "Requested sample not found" in e.message:
                    raise SampleAbsent("No such sample in AutoFocus")
                raise e

        async def _coro():

            try:
                resp = await APIRequest(url, post_data=post_data, async_request=self.async_request).run()
                return _parse_resp_data(resp['json'])
            except ClientError as e:
                if "Requested sample not found" in e.message:
                    raise SampleAbsent("No such sample in AutoFocus")
                raise e

        return _coro()
