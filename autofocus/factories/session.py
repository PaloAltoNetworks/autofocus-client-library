from .base import AutoFocusAPI
from ..exceptions import _InvalidSampleData
from ..config import get_logger


class SessionFactory(AutoFocusAPI):
    """
    SessionFactory is a class to handle fetching an instantiating Session objects. See Session for details
    """

    def count(self, query):
        """

        The SessionFactory.count method returns the count of sessions matching the query offered

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
                    session_count = SessionFactory().count({'field':'session.malware', 'value':1, 'operator':'is'}):
                        pass # Do something with the session
                except ServerError:
                    pass # Something happened to the server
                except ClientError:
                    pass # The client did something stupid, likely a bad query was passed

                # Python dictionary with the query parameters
                try:
                    session = SessionFactory().count({'field':'session.malware', 'value':1, 'operator':'is'})
                except StopIteration:
                    pass # No results found
                except ServerError:
                    pass # Something happened to the server
                except ClientError:
                    pass # The client did something stupid, likely a bad query was passed
        Args:
            query str: The query to run against autofocus (will also take dicts per examples)

        Returns:
            int: the number of sessions matching the query

        Raises
        ------
            ClientError: In the case that the client did something unexpected
            ServerError: In the case that the client did something unexpected

        """  # noqa
        if not self.async_request:
            return self._api_count("/sessions/search", query, None)

        async def _coro():
            return await self._api_count("/sessions/search", query, None)
        return _coro()

    def scan(self, query, limit=0):
        """

        The SessionFactory.scan method is a factory to return Session object instances. These correspond to values returned
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
                    for session in SessionFactory().scan({'field':'session.malware', 'value':1, 'operator':'is'}):
                        pass # Do something with the session
                except ServerError:
                    pass # Something happened to the server
                except ClientError:
                    pass # The client did something stupid, likely a bad query was passed

                # Python dictionary with the query parameters
                try:
                    session = SessionFactory().search({'field':'session.malware', 'value':1, 'operator':'is'}).next()
                except StopIteration:
                    pass # No results found
                except ServerError:
                    pass # Something happened to the server
                except ClientError:
                    pass # The client did something stupid, likely a bad query was passed
        Args:
            query str: The query to run against autofocus (will also take dicts per examples)
            limit Optional[int]: Limit the number of returned results.

        Yields:
            Session: sample objects as they are paged from the REST service

        Raises
        ------
            ClientError: In the case that the client did something unexpected
            ServerError: In the case that the client did something unexpected

        """  # noqa
        from ..models.session import Session

        if not self.async_request:
            def _not_coro():
                for res in self._api_scan("/sessions/search", query, None, None, limit):
                    try:
                        yield Session(**res['_source'])
                    except _InvalidSampleData as e:
                        get_logger().debug(e, exc_info=True)
            return _not_coro()

        async def _coro():
            async for res in self._api_scan("/sessions/search", query, None, None, limit):
                try:
                    yield Session(**res['_source'])
                except _InvalidSampleData as e:
                    get_logger().debug(e, exc_info=True)
        return _coro()

    def search(self, query, sort_by="tstamp", sort_order="asc", limit=0):
        """

        The SessionFactory.search method is a factory to return Session object instances.
        These correspond to values returned by the query supplied.

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
                    for session in SessionFactory().search({'field':'session.malware', 'value':1, 'operator':'is'}):
                        pass # Do something with the session
                except ServerError:
                    pass # Something happened to the server
                except ClientError:
                    pass # The client did something stupid, likely a bad query was passed

                # Python dictionary with the query parameters
                try:
                    session = SessionFactory().search({'field':'session.malware', 'value':1, 'operator':'is'}).next()
                except StopIteration:
                    pass # No results found
                except ServerError:
                    pass # Something happened to the server
                except ClientError:
                    pass # The client did something stupid, likely a bad query was passed
        Args:
            query str:The query to run against autofocus (will also take dicts per examples)
            sort_by Optional[str]: The field to sort results by
            sort_order Optional[str]; asc or desc sort order
            limit Optional[int]: Limit the number of returned results.

        Yields:
            Session: sample objects as they are paged from the REST service

        Raises
        ------
            ClientError: In the case that the client did something unexpected
            ServerError: In the case that the client did something unexpected

        """  # noqa
        from ..models.session import Session

        if not self.async_request:
            def _not_coro():
                for res in self._api_search("/sessions/search", query, None, sort_by, sort_order, None, limit):
                    yield Session(session_id=res.get('_id'), **res['_source'])
            return _not_coro()

        async def _coro():
            async for res in self._api_search("/sessions/search", query, None, sort_by, sort_order, None, limit):
                yield Session(session_id=res.get('_id'), **res['_source'])
        return _coro()
