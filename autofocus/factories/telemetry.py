from .base import AutoFocusAPI
from ..exceptions import ClientError


class TelemetryFactory(AutoFocusAPI):
    """
    TelemetryFactory is a class to handle fetching an instantiating Telemetry objects. See Telemetry for details
    """

    def search(self, query, time_frame='5m', sort_by="triggers", sort_order="desc"):
        """
        Notes: See Telemetry.search documentation
        """

        if not time_frame or time_frame not in ('4h', '5m'):
            raise ClientError("time_frame should be 4h or 5m in Telemetry Search")

        page_size = 1000

        post_data = {
            "query": query,
            "from": 1,
            "size": page_size,
            "sort": sort_by,
            "dir": sort_order
        }

        class _break_loop(Exception):
            pass

        def _parse_resp(resp):

            resp_data = resp['json']

            total = resp_data['total']

            if not resp_data.get('telemetry'):
                raise _break_loop()

            for telem in resp_data['telemetry']:
                yield telem

            if total < (page_size * (post_data['from'] + 1)):
                raise _break_loop()

            post_data['from'] += 1

        if not self.async_request:
            def _not_coro():
                while True:
                    try:
                        for res in _parse_resp(self._api_request(f"/telemetry/{time_frame}/search",
                                                                 post_data=post_data)):
                            yield res
                    except _break_loop:
                        break
            return _not_coro()

        async def _coro():
            while True:
                try:
                    for res in _parse_resp(await self._api_request(f"/telemetry/{time_frame}/search",
                                                                   post_data=post_data)):
                        yield res
                except _break_loop:
                    break
        return _coro()


class TelemetryAggregateFactory(AutoFocusAPI):
    """TelemetryAggregateFactory is a class to handle fetching an instantiating TelemetryAggregate objects.

    See TelemetryAggregate for details
    """

    def search(self, query, agg_by='top-threats', sort_by="triggers", sort_order="desc"):
        """
        Notes: See TelemetryAggregate.search documentation
        """

        valid_aggs = [
            "top-threats"
            "top-files"
            "usage"
            "devices"
            "customers"
        ]

        if not agg_by not in valid_aggs:
            raise ClientError(f"agg_by should be in the following list: {','.join(valid_aggs)}")

        page = 1
        page_size = 1000
        total = None

        while True:

            post_data = {
                "query": query,
                "page": page,
                "perPage": page_size,
                "sort": sort_by,
                "dir": sort_order
            }

            resp = self._api_request(f"/telemetry/{agg_by}", post_data=post_data)

            resp_data = resp['json']

            if total is None:
                total = resp_data['total']

            if not resp_data.get('telemetry'):
                break

            for telem in resp_data['telemetry']:
                yield telem

            if total < (page_size * page):
                break

            page += 1
