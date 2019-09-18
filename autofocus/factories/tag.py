import json
import asyncio
import math

from .base import AutoFocusAPI
from ..exceptions import ClientError
from ..exceptions import TagAbsent
from ..exceptions import TagGroupAbsent


class TagGroupCache:

    def __init__(self):
        self._cache = {}

    def get(self, tag_group_name):
        return self._cache.get(tag_group_name, None)

    def add(self, tag_group):
        self._cache[tag_group.name] = tag_group
        return self._cache[tag_group.name]

    def clear(self, tag_group):
        del self._cache[tag_group.name]


class TagCache:

    def __init__(self):
        self._cache = {}

    def get(self, tag_name):
        return self._cache.get(tag_name, None)

    def add(self, tag):
        self._cache[tag.public_name] = tag
        return self._cache[tag.public_name]

    def clear(self, tag):
        del self._cache[tag.public_name]


class TagFactory(AutoFocusAPI):
    """
    TagFactory is a class to handle fetching an instantiating Tag objects.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache = kwargs.get("cache") or TagCache()

    def get_tags_by_group(self, group_name):
        """
        Notes: See TagGroup.get for documentation
        """
        return self.search([{"field": "tag_group", "operator": "is", "value": group_name}])

    def search(self, query, *args, **kwargs):
        """
        Examples:
            tags = TagFactory().search([{"field":"tag_name","operator":"contains","value":"jwhite"}])
            # Or as a string
            tags = TagFactory().search('[{"field":"tag_name","operator":"contains","value":"jwhite"}]')
        Notes:
            Tag objects must be in a list, like in the example
        Args:
            query (str): The string or object that you wish to query for
            scope (str): The scope of the tags you want listed, acceptable values are -
                Visible, Private, Public, Unit42, Mine, Commodity. Defaults to Visible
            sortBy (Optional[str]): The field to sort results by, acceptable values are - name, status, count, lasthit,
                upVotes, downVotes. Defaults to name
            order (str): The direction to sort, acceptable values are "asc" or "desc", Defaults to asc

        Returns:
            List[Tag]: as list of Tag objects based on the arguments offered.

        Raises:
            ClientError: In the case that the client did something unexpected
            ServerError: In the case that the client did something unexpected

        Examples:
            for tag in TagFactory().list():
                print tag.count
        """

        kwargs['query'] = query

        try:
            if type(query) not in (list, dict):
                kwargs['query'] = json.loads(query)
        except Exception:
            raise ClientError("Query is not valid JSON")

        return self.list(*args, **kwargs)

    def list(self, *args, **kwargs):
        """
        Args:
            scope (str): The scope of the tags you want listed, acceptable values are -
                Visible, Private, Public, Unit42, Mine, Commodity. Defaults to Visible
            sortBy (Optional[str]): The field to sort results by, acceptable values are - name, status, count, lasthit,
                upVotes, downVotes. Defaults to name
            order (str): The direction to sort, acceptable values are "asc" or "desc", Defaults to asc


        Returns:
            List[Tag]: as list of Tag objects based on the arguments offered.

        Raises:
            ClientError: In the case that the client did something unexpected
            ServerError: In the case that the client did something unexpected

        Examples:
            for tag in TagFactory().list():
                print tag.count
        """
        from ..models.tag import Tag

        kwargs['scope'] = kwargs.get("scope", "visible").lower()
        kwargs['sortBy'] = kwargs.get("sortBy", "name")
        kwargs['order'] = kwargs.get("order", "asc")
        kwargs['pageSize'] = 200
        kwargs['pageNum'] = 0

        if args:
            kwargs['scope'] = str(args[0]).lower()

        def _parse_tag_response(resp_data):
            res = []
            for tag_data in resp_data['tags']:
                tag = self._cache.add(Tag(**tag_data))
                res.append(tag)
            return res

        if not self.async_request:

            def _get_tag_data():
                return self._api_request("/tags", post_data=kwargs)['json']

            resp_data = _get_tag_data()
            results = _parse_tag_response(resp_data)

            if resp_data['total_count'] <= kwargs['pageSize']:
                return results

            for page_num in range(1, int(math.ceil(resp_data['total_count'] / kwargs['pageSize']))):
                kwargs['pageNum'] = page_num
                results += _parse_tag_response(_get_tag_data())

            return results

        async def _coro():

            async def _get_tag_data(page_num):
                post_data = kwargs.copy()
                post_data['pageNum'] = page_num
                return (await self._api_request("/tags", post_data=post_data))['json']

            results = []
            resp_data = await _get_tag_data(0)
            results += _parse_tag_response(resp_data)

            if resp_data['total_count'] <= kwargs['pageSize']:
                return results

            tasks = []
            for page_num in range(1, int(math.ceil(resp_data['total_count'] / kwargs['pageSize']))):
                tasks.append(_get_tag_data(page_num))

            for res in await asyncio.gather(*tasks):
                results += _parse_tag_response(res)

            return results

        return _coro()

    def get(self, tag_name, use_cache=True, async_request=None):
        """
        Args:
            tag_name (str): The name of the tag to pull an object for
            use_cache (bool): Whether to use internal caching mechanisms or not, defaults to True
            async_request (AsyncReq): A AsyncRequest object, signalling for an asyncronous requests, overrides the attribute

        Returns:
            Tag: an instance of Tag for the given tag name
            asyncio.coroutine: A coroutine when called as an async request

        Raises:
            SampleAbsent: Raises a key error when the tag does not exist
            ClientError: In the case that the client did something unexpected
            ServerError: In the case that the client did something unexpected

        Examples:
            try:
                tag = TagFactory().get("Made up tag name")
            except TagAbsent:
                pass # Tag didn't exist
        """  # noqa
        from ..models.tag import Tag

        def _post(resp):
            resp_data = resp['json']
            tag_data = resp_data['tag']
            tag_data['related_tag_names'] = resp_data.get("related_tags", [])
            tag_data['tag_searches'] = resp_data.get("tag_searches", [])
            tag_data['tag_groups'] = resp_data.get("tag_groups", [])

            tag = self._cache.add(Tag(**tag_data))

            return tag

        async def _async_do():
            try:
                return await self.async_api_request("/tag/" + tag_name, session=async_request.session)
            except ClientError as e:
                if e.response['status_code'] == 404 or e.response['status_code'] == 409:
                    raise TagAbsent("No such tag exists")
                raise e

        if not self.async_request:

            if use_cache:
                tag = self._cache.get(tag_name)
                if tag:
                    return tag
            try:
                return _post(self._api_request("/tag/" + tag_name))
            except ClientError as e:
                if e.response['status_code'] == 404 or e.response['status_code'] == 409:
                    raise TagAbsent("No such tag exists")
                raise e

        async def _coro():
            if use_cache:
                tag = self._cache.get(tag_name)
                if tag:
                    return tag
            try:
                return _post(await self._api_request("/tag/" + tag_name))
            except ClientError as e:
                if e.response['status_code'] == 404 or e.response['status_code'] == 409:
                    raise TagAbsent("No such tag exists")
                raise e
        return _coro()


class TagGroupFactory(AutoFocusAPI):

    tag_factory = TagFactory()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache = kwargs.get("cache") or TagGroupCache()
        if not self.async_request and self.tag_factory.async_request:
            self.async_request = self.tag_factory.async_request
        # If we are being called async, we need to update our tag_factory instance to be async
        elif self.async_request:
            self.tag_factory = TagFactory(async_request=self.async_request)

    def get(self, group_name, use_cache=True):
        """
        Args:
            group_name (str): The name of the group to pull

        Returns:
            TagGroup: an instance of TagGroup for the given TagGroup name

        Raises:
            SampleAbsent: Raises a key error when the tag does not exist
            ClientError: In the case that the client did something unexpected
            ServerError: In the case that the client did something unexpected

        Examples:
            try:
                tag_group = TagGroupFactory().get("OSX")

                for tag in tag_group:
                    print tag.public_name

            except TagGroupAbsent:
                pass # Tag group didn't exist
        """

        if not self.async_request:

            if use_cache:
                group = self._cache.get(group_name)
                if group:
                    return group

            tags = self.tag_factory.get_tags_by_group(group_name)

            if not tags:
                raise TagGroupAbsent(f"Unable to find tag group {group_name}")

            group = [v for v in tags[0].groups if v.name == group_name][0]

            object.__setattr__(group, "tags", tags)

            if use_cache:
                group = self._cache.add(group)

            return group

        async def _coro():

            if use_cache:
                group = self._cache.get(group_name)
                if group:
                    return group

            tags = await self.tag_factory.get_tags_by_group(group_name)

            if not tags:
                raise TagGroupAbsent(f"Unable to find tag group {group_name}")

            group = [v for v in tags[0].groups if v.name == group_name][0]

            object.__setattr__(group, "tags", tags)

            if use_cache:
                group = self._cache.add(group)

            return group

        return _coro()
