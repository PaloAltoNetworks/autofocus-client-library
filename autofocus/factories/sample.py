import re
import asyncio

from ..config import get_logger
from .base import AutoFocusAPI
from ..exceptions import SampleAbsent
from ..exceptions import ClientError
from ..exceptions import _InvalidSampleData


class SampleFactory(AutoFocusAPI):
    """
    SampleFactory is a class to handle fetching an instantiating Sample objects. See Sample for details
    """
    def list(self, sha256s, attributes=None, concurrency=3):
        """

        The SampleFactory.list method is a factory to return Sample object instances.
        This correspond to the list of hashes offered.

        Notes
        -----
            This is a conveneience method that utilizes the Sample.scan function, pulling 1k samples per API request.
             It returns a generator for iterating on the Sample objects.

             THERE IS NO ERROR RETURNED IF A SHA256 IS NOT FOUND. If you need to ensure that 100% of the samples are in
             AF, you'll need to keep track of your original list and compare it to the results.

            Argument validation is done via the REST service. There is no client side validation of arguments. See the
            `following page <https://www.paloaltonetworks.com/documentation/autofocus/autofocus/autofocus_admin_guide/autofocus-search/work-with-the-search-editor.html>`_
            for details on how searching works in the UI and how to craft a query for the API.

        Examples
        --------
            Using the search class method::

                # Python dictionary with the query parameters
                try:
                    for sample in SampleFactory().list([hash1, hash2]):
                        sample # Do something with the sample object
                except ServerError:
                    pass # Something happened to the server
                except ClientError:
                    pass # The client did something stupid, likely a bad query was passed
        Args:
            sha25s List[str]: The sha256s to look up
            attributes Optional[str]: A str or list of strs for attributes to be included in the results. Defaults to all attributes

        Yields:
            Sample: sample objects as they are paged from the REST service

        Raises
        ------

            ClientError: In the case that the client did something unexpected
            ServerError: In the case that the client did something unexpected

        """ # noqa

        sha_lists = []

        def chunks(list_, n):
            res = []
            for i in range(0, len(list_), n):
                res.append(list_[i:i + n])
            return res

        sha_lists = chunks(sha256s, 1000)

        if not self.async_request:
            def _not_coro():

                for sha_list in sha_lists:

                    query = {
                        "operator": "all",
                        "children": [
                            {
                                "field": "sample.sha256",
                                "operator": "is in the list",
                                "value": sha_list
                            }
                        ]
                    }

                    for sample in self.search(query, attributes=attributes):
                        yield sample
            return _not_coro()

        async def _coro():

            async def _res(query):
                return [v async for v in self.search(query, attributes=attributes)]

            for sha_chunks in chunks(sha_lists, concurrency):

                tasks = []

                for sha_list in sha_chunks:

                    query = {
                        "operator": "all",
                        "children": [
                            {
                                "field": "sample.sha256",
                                "operator": "is in the list",
                                "value": sha_list
                            }
                        ]
                    }

                    tasks.append(_res(query))

                for res in await asyncio.gather(*tasks):
                    for r in res:
                        yield r

        return _coro()

    def search(self, query, scope="global", sort_by="create_date", sort_order="asc", attributes=None, limit=0):
        """

        The SampleFactory.search method is a factory to return Sample object instances. These correspond to values returned
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
                    for sample in SampleFactory().search({'field':'sample.malware', 'value':1, 'operator':'is'}):
                        pass # Do something with the sample
                except ServerError:
                    pass # Something happened to the server
                except ClientError:
                    pass # The client did something stupid, likely a bad query was passed

                # Python dictionary with the query parameters
                try:
                    sample = SampleFactory().search({'field':'sample.malware', 'value':1, 'operator':'is'}).next()
                except StopIteration:
                    pass # No results found
                except ServerError:
                    pass # Something happened to the server
                except ClientError:
                    pass # The client did something stupid, likely a bad query was passed
        Args:
            query str:The query to run against autofocus (will also take dicts per examples)
            scope Optional[str]:The scope of the search you're running. Defaults to "global"
            sort_by Optional[str]: The field to sort results by
            sort_order Optional[str]; asc or desc sort order
            attributes Optional[str]: A str or list of strs for attributes to be included in the results. Defaults to all attributes
            limit Optional[int]: Limit the numder of returned results.

        Yields:
            Sample: sample objects as they are paged from the REST service

        Raises
        ------

            ClientError: In the case that the client did something unexpected
            ServerError: In the case that the server did something unexpected

        """ # noqa
        from ..models.sample import Sample

        fields = []
        if attributes:
            if type(attributes) in (str, str):
                attributes = [attributes]
            for attr in attributes:
                if attr not in Sample.attributes_to_known_fields:
                    raise ClientError(f"Unknown attribute: {attr}")

                fields.append(Sample.attributes_to_known_fields[attr])

        if not self.async_request:

            def _not_coro():
                for res in self._api_search("/samples/search", query, scope, sort_by, sort_order, fields, limit):
                    try:
                        if attributes:
                            attrib_limit = attributes if not isinstance(attributes, str) else [attributes]
                            res['_source']['_limit_attributes_to'] = attrib_limit
                        if 'sha256' not in res['_source']:
                            res['_source']['sha256'] = res['_id']
                        yield Sample(**res['_source'])
                    except _InvalidSampleData as e:
                        get_logger().debug(e, exc_info=True)
            return _not_coro()

        async def _coro():
            async for res in self._api_search("/samples/search", query, scope, sort_by, sort_order, fields, limit):
                try:
                    if attributes:
                        attrib_limit = attributes if not isinstance(attributes, str) else [attributes]
                        res['_source']['_limit_attributes_to'] = attrib_limit
                    if 'sha256' not in res['_source']:
                        res['_source']['sha256'] = res['_id']
                    yield Sample(**res['_source'])
                except _InvalidSampleData as e:
                    get_logger().debug(e, exc_info=True)
        return _coro()

    def count(self, query, scope="global"):
        """
         The SampleFactory.count method returns the total number of samples matching the query for the given scope

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
                     total_sample_count = SampleFactory().count({'field':'sample.malware', 'value':1, 'operator':'is'})
                 except ServerError:
                     pass # Something happened to the server
                 except ClientError:
                     pass # The client did something stupid, likely a bad query was passed

                 # Python dictionary with the query parameters
                 try:
                     total_sample_count = SampleFactory().count({'field':'sample.malware', 'value':1, 'operator':'is'})
                 except StopIteration:
                     pass # No results found
                 except ServerError:
                     pass # Something happened to the server
                 except ClientError:
                     pass # The client did something stupid, likely a bad query was passed
         Args:
             query str:The query to run against autofocus (will also take dicts per examples)
             scope Optional[str]:The scope of the search you're running. Defaults to "global"

         Returns:
             int: the number of samples matching the query & scope

         Raises
         ------

             ClientError: In the case that the client did something unexpected
             ServerError: In the case that the client did something unexpected

         """  # noqa
        return self._api_count("/samples/search", query, scope)

    def scan(self, query, scope="global", attributes=None, limit=0):
        """

        The SampleFactory().scan method is a factory to return Sample object instances. These correspond to values returned
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
                    for sample in SampleFactory().scan({'field':'sample.malware', 'value':1, 'operator':'is'}):
                        pass # Do something with the sample
                except ServerError:
                    pass # Something happened to the server
                except ClientError:
                    pass # The client did something stupid, likely a bad query was passed

                # Python dictionary with the query parameters
                try:
                    sample = SampleFactor().scan({'field':'sample.malware', 'value':1, 'operator':'is'}).next()
                except StopIteration:
                    pass # No results found
                except ServerError:
                    pass # Something happened to the server
                except ClientError:
                    pass # The client did something stupid, likely a bad query was passed
        Args:
            query str:The query to run against autofocus (will also take dicts per examples)
            scope Optional[str]:The scope of the search you're running. Defaults to "global"
            attributes Optional[str]: A str or list of strs for attributes to be included in the results. Defaults to all attributes
            limit Optional[int]: Limit the numder of returned results.

        Yields:
            Sample: sample objects as they are paged from the REST service

        Raises
        ------

            ClientError: In the case that the client did something unexpected
            ServerError: In the case that the client did something unexpected

        """  # noqa
        from ..models.sample import Sample

        fields = []
        if attributes:
            if type(attributes) in (str, str):
                attributes = [attributes]
            for attr in attributes:
                if attr not in Sample.attributes_to_known_fields:
                    raise ClientError(f"Unknown attribute: {attr}")

                fields.append(Sample.attributes_to_known_fields[attr])

        if self.async_request:
            async def _coro():
                async for res in self._api_scan("/samples/search", query, scope, fields, limit):
                    try:
                        if attributes:
                            attrib_limit = attributes if not isinstance(attributes, str) else [attributes]
                            res['_source']['_limit_attributes_to'] = attrib_limit
                        if 'sha256' not in res['_source']:
                            res['_source']['sha256'] = res['_id']
                        yield Sample(**res['_source'])
                    except _InvalidSampleData:
                        pass
            return _coro()

        def _not_coro():
            for res in self._api_scan("/samples/search", query, scope, fields, limit):
                try:
                    if attributes:
                        attrib_limit = attributes if not isinstance(attributes, str) else [attributes]
                        res['_source']['_limit_attributes_to'] = attrib_limit
                    if 'sha256' not in res['_source']:
                        res['_source']['sha256'] = res['_id']
                    yield Sample(**res['_source'])
                except _InvalidSampleData:
                    pass

        return _not_coro()

    def get(self, hash, attributes=None):
        """
        Args:
            hash (str): either a md5, sha1, or sha256 hash of the sample needed
            attributes Optional[str]: A str or list of strs for attributes to be included in the results. Defaults to all attributes

        Returns:
            Sample: Instance of Sample that matches the hash offered

        Raises:
            ClientError: In the case that the client did something unexpected or an invalid hash was offered
            ServerError: In the case that the client did something unexpected
            SampleAbsent in the case that the sample is absent in autofocus

        Examples
        --------
            Examples using the get method::

                try:
                    sample = SampleFactory().get("31a9133e095632a09a46b50f15b536dd2dc9e25e7e6981dae5913c5c8d75ce20")
                    sample = SampleFactory().get("97a174dbc51a2c4f9cad05b6fc9af10d3ba7c919")
                    sample = SampleFactory().get("a1f19a3ebd9213d2f0d895ec86a53390")
                except SampleAbsent:
                    pass # Sample didn't exist

        """  # noqa

        if not re.match(r'^([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$', hash):
            raise ClientError("Argument mush be a valid md5, sha1, or sha256 hash")

        res = None

        query = {"operator": "is", "value": hash}
        if len(hash) == 32:
            query['field'] = "sample.md5"
        elif len(hash) == 40:
            query['field'] = "sample.sha1"
        elif len(hash) == 64:
            query['field'] = "sample.sha256"

        if not self.async_request:

            res = None

            try:
                for sample in self.search(query, attributes=attributes):
                    res = sample
            except _InvalidSampleData:
                raise SampleAbsent("Sample data is incomplete in AutoFocus")
            except StopIteration:
                pass

            if not res:
                raise SampleAbsent("No such hash found in AutoFocus")

            return res

        async def _coro():

            res = None

            try:
                async for sample in self.search(query, attributes=attributes):
                    res = sample
            except _InvalidSampleData:
                raise SampleAbsent("Sample data is incomplete in AutoFocus")
            except StopIteration:
                pass

            if not res:
                raise SampleAbsent("No such hash found in AutoFocus")

            return res

        return _coro()

    def aggregate(self, query, scope="global", field="malware", size=10):

        from ..factories.base import AggRequest

        post_data = {
            "field": field,
            "scope": scope,
            "query": query,
            "size": size
        }

        return AggRequest("/samples/aggregate/search/", post_data=post_data, async_request=self.async_request).run()
