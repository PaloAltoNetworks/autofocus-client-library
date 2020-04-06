import asyncio
import json
import time
import ssl

import aiohttp
import requests

from ..config import AF_APIKEY
from ..config import SSL_CERT
from ..config import SSL_VERIFY
from ..config import _BASE_URL
from ..config import get_logger
from ..exceptions import AutoFocusException
from ..exceptions import ClientError
from ..exceptions import GrauduatingSleepError
from ..exceptions import RedirectError
from ..exceptions import ServerError
from ..version import __version__


class ClassPropertyMeta(type):
    def __setattr__(self, key, value):
        obj = self.__dict__.get(key, None)
        if type(obj) is classproperty:
            return obj.__set__(self, value)
        return super().__setattr__(key, value)


class classproperty(object):
    """
    Similar to @property but used on classes instead of instances.
    The only caveat being that your class must use the
    classproperty.meta metaclass.
    Class properties will still work on class instances unless the
    class instance has overidden the class default. This is no different
    than how class instances normally work.
    Derived from: https://stackoverflow.com/a/5191224/721519
    class Z(object, metaclass=classproperty.meta):
        @classproperty
        def foo(cls):
            return 123
        _bar = None
        @classproperty
        def bar(cls):
            return cls._bar
        @bar.setter
        def bar(cls, value):
            return cls_bar = value
    Z.foo  # 123
    Z.bar  # None
    Z.bar = 222
    Z.bar  # 222
    """

    meta = ClassPropertyMeta

    def __init__(self, fget, fset=None):
        self.fget = self._fix_function(fget)
        self.fset = None if fset is None else self._fix_function(fset)

    def __get__(self, instance, owner=None):
        if not issubclass(type(owner), ClassPropertyMeta):
            raise TypeError(
                f"Class {owner} does not extend from the required "
                f"ClassPropertyMeta metaclass"
            )
        return self.fget.__get__(None, owner)()

    def __set__(self, owner, value):
        if not self.fset:
            raise AttributeError("can't set attribute")
        if type(owner) is not ClassPropertyMeta:
            owner = type(owner)
        return self.fset.__get__(None, owner)(value)

    def setter(self, fset):
        self.fset = self._fix_function(fset)
        return self

    _fn_types = (type(__init__), classmethod, staticmethod)

    @classmethod
    def _fix_function(cls, fn):
        if not isinstance(fn, cls._fn_types):
            raise TypeError("Getter or setter must be a function")
        # Always wrap in classmethod so we can call its __get__ and not
        # have to deal with difference between raw functions.
        if not isinstance(fn, (classmethod, staticmethod)):
            return classmethod(fn)
        return fn


class RetryRequest(Exception):
    pass


class AFConnectionError(Exception):
    pass


class AsyncRequest:

    def __init__(self, session=None, callback=None, loop=None):
        self.callback = callback
        self.session = session
        self.loop = loop


class BaseFactory:

    async_request = None

    def __init__(self, **kwargs):
        for k, v in list(kwargs.items()):
            setattr(self, k, v)

    def __repr__(self):
        return self.__dict__.__str__()


class BaseRequest:

    url = ""
    base_url = _BASE_URL
    path = ""
    params = None
    post_data = None
    allow_redirects = False
    verify_ssl = SSL_VERIFY
    cert = SSL_CERT
    headers = None
    logger = get_logger()
    session = None
    user_agent = "BaseRequest"
    async_request = None

    def __init__(self, **kwargs):
        for k, v in list(kwargs.items()):
            setattr(self, k, v)

    def __repr__(self):
        return str(self.__dict__)

    async def _async_http_post(self):
        session = self.async_request.session
        if self.verify_ssl and not self.cert:
            ssl_context = None  # aiohttp creates a default context
        elif self.cert and self.verify_ssl:
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=self.cert)
        else:
            ssl_context = False  # No ssl check
        try:
            if not session:
                async with aiohttp.ClientSession() as session:
                    async with session.post(self.url, params=self.params, headers=self.headers,
                                            data=json.dumps(self.post_data),
                                            allow_redirects=self.allow_redirects, ssl=ssl_context) as resp:
                        return {
                            "content": await resp.text(),
                            "json": await resp.json(),
                            "status_code": resp.status
                        }
            async with session.post(self.url, params=self.params, headers=self.headers,
                                    data=json.dumps(self.post_data), allow_redirects=self.allow_redirects,
                                    ssl=ssl_context) as resp:
                return {
                    "content": await resp.text(),
                    "json": await resp.json(),
                    "status_code": resp.status
                }
        except aiohttp.ClientConnectionError as e:
            raise AFConnectionError(e)

    def _http_post(self):
        try:
            resp = requests.post(self.url, params=self.params, headers=self.headers, data=json.dumps(self.post_data),
                                 allow_redirects=False, verify=self.verify_ssl, cert=self.cert)
            return {
                'status_code': resp.status_code,
                'content': resp.text,
                'json': resp.json()
            }
        except requests.ConnectionError as e:
            raise AFConnectionError(e)

    def http_post(self):
        if self.async_request:
            return self._async_http_post()
        return self._http_post()


class GraduatingSleep:

    init_sleep_duration = .1
    max_sleep_duration = 600

    def __init__(self):
        self.counter = 0
        self.total_sleep_time = 0

    async def _async_sleep(self):
        sleep_time = 0
        if self.counter >= 3:
            sleep_time = 1

        self.total_sleep_time += sleep_time

        if self.total_sleep_time >= self.__class__.max_sleep_duration:
            raise GrauduatingSleepError()

        if sleep_time:
            await asyncio.sleep(sleep_time)

        self.counter += 1

    def sleep(self, async_sleep=False):
        """Graduating sleep time. Sleep for progressively longer until we get results. This logic will allow us to
        check results up to 185 times within 10 minutes. If we haven't gotten a full result set in 10 minutes,
        raise an exception
        """

        if async_sleep:
            return self._async_sleep()
        # sleep_time = self.__class__.init_sleep_duration
        # sleep_time += sleep_time * math.floor(self.counter / 3)

        # Changing logic to handle a 1 second sleep after three attempts

        sleep_time = 0
        if self.counter >= 3:
            sleep_time = 1

        self.total_sleep_time += sleep_time

        if self.total_sleep_time >= self.__class__.max_sleep_duration:
            raise GrauduatingSleepError()

        if sleep_time:
            time.sleep(sleep_time)

        self.counter += 1


class APIRequest(BaseRequest):

    e_code_skips = 0
    api_key = AF_APIKEY
    af_cookie = ""
    user_agent = "GSRT AutoFocus Client Library/" + __version__

    def _prep_post_data(self, post_data):

        sort_by = post_data.pop("sort_by", None)
        sort_dir = post_data.pop("sort_dir", None)

        if 'sort_by' in post_data:
            post_data['sort'] = {
                sort_by: {
                    "order": sort_dir if sort_dir else "asc"
                }
            }

        if 'fields' in post_data and type(post_data['fields']) is str:
            post_data['fields'] = [post_data['fields']]

        if 'query' in post_data:
            query = post_data['query']

            if type(query) is str:
                post_data['query'] = json.loads(query)
            elif type(query) is dict:
                if 'field' in query:
                    post_data['query'] = {"operator": "all", "children": [query]}
                else:
                    post_data['query'] = query
            elif type(query) is not list:
                raise ValueError("Query must be a valid AutoFocus search string or object (dictionary)")

        return post_data

    def _validate_response(self, resp):
        pass

    def __init__(self, path, **kwargs):

        self.api_key = self.api_key or kwargs.get("api_key")
        if not self.api_key:
            raise ClientError("API key is not set. Library requires AutoFocusAPI.api_key to be set, or apikey"
                              "to be provided via configuration file.")

        self.post_data = self._prep_post_data(kwargs.get("post_data") or self.post_data or {})
        self.params = kwargs.get("params") or self.params or {}
        self.headers = kwargs.get("headers") or self.headers or {}
        self.af_cookie = kwargs.get("af_cookie") or self.af_cookie

        self.headers['Content-Type'] = self.headers.get("Content-Type", "application/json")
        self.headers['User-Agent'] = self.headers.get("User-Agent", self.user_agent)

        self.post_data["apiKey"] = self.api_key
        self.path = path
        self.url = self.base_url + path.replace(self.base_url, "")
        self.logger.debug(f"Request [{self.url}]: {self.post_data}")
        self.session = kwargs.get("session") or self.session
        self.async_request = kwargs.get("async_request") or self.async_request

    def _api_request_handle_response(self, resp):

        self.logger.debug(f"Response [{resp['status_code']}]: {resp['content']}")

        if not (200 <= resp['status_code'] < 300):

            message = resp['content']

            if self.af_cookie:
                message = f"AF_COOKIE - {self.af_cookie}\n{message}"

            if 300 <= resp['status_code'] < 400:
                raise RedirectError("Unexpected redirect", resp)

            if 400 <= resp['status_code'] < 500:
                raise ClientError(message, resp)

            if 500 <= resp['status_code'] < 600:

                # Retrying E101x errors, per Tarun Singh
                try:
                    resp_data = resp['json']
                    if resp_data['code'] in ("E1015", "E1016", "E1017", "E1100", "E1201"):
                        raise RetryRequest(f"Too many ECODE errors - {resp_data['code']}")
                except requests.ConnectionError as e:
                    raise RetryRequest(e)
                except Exception:
                    pass

                raise ServerError(message, resp)

        return resp

    async def _async_api_request(self):

        try:
            return self._api_request_handle_response(await self.http_post())
        except RetryRequest as e:
            if self.e_code_skips < 3:
                self.e_code_skips += 1
                return await self._async_api_request()
            else:
                raise ServerError(str(e), None)
        except AFConnectionError as e:
            raise ServerError(str(e), None)

    def _api_request(self):

        try:
            return self._api_request_handle_response(self.http_post())
        except RetryRequest as e:
            if self.e_code_skips < 3:
                self.e_code_skips += 1
                return self._api_request()
            else:
                raise ServerError(str(e), None)
        except AFConnectionError as e:
            raise ServerError(str(e), None)

    def api_request(self):
        if self.async_request:
            return self._async_api_request()
        return self._api_request()

    def run(self):
        return self.api_request()


class ResultRequest(APIRequest):

    expected_size = 0

    def _build_url(self, *args, **kwargs):
        return "/" + args[0].split("/")[1] + "/results/" + kwargs.get("af_cookie", "")

    def __init__(self, *args, **kwargs):

        args = list(args)

        # We need to transform the request URL
        args[0] = self._build_url(*args, **kwargs)

        super().__init__(*args, **kwargs)
        self.expected_size = kwargs.get("expected_size", self.expected_size)

    def _check_if_results_complete(self, resp_data):

        result_size = len(resp_data.get('hits', []))

        # If we've gotten our bucket size worth of data, or the query has complete
        if (self.expected_size and result_size == self.expected_size) or not resp_data.get('af_in_progress'):
            return True

        return False

    async def _async_run(self):

        sleeper = GraduatingSleep()

        resp_data = {}

        while True:

            try:
                resp = await self.api_request()
            except AutoFocusException:
                raise
            except Exception:
                raise ServerError(f"AF_COOKIE - {self.af_cookie}\nServer sent malformed response {resp['content']}",
                                  resp)

            self._validate_response(resp)
            resp_data = resp['json']

            if self._check_if_results_complete(resp_data):
                break

            try:
                await sleeper.sleep(async_sleep=True)
            except GrauduatingSleepError:
                raise ServerError(f"AF_COOKIE - {self.af_cookie}\nTimed out while pulling results", resp)

        return resp_data

    def run(self):

        if self.async_request:
            return self._async_run()

        sleeper = GraduatingSleep()

        resp_data = {}

        while True:

            try:
                resp = self.api_request()
            except AutoFocusException:
                raise
            except Exception:
                raise ServerError(f"AF_COOKIE - {self.af_cookie}\nServer sent malformed response {resp['content']}",
                                  resp)

            self._validate_response(resp)
            resp_data = resp['json']

            if self._check_if_results_complete(resp_data):
                break

            try:
                sleeper.sleep()
            except GrauduatingSleepError:
                raise ServerError(f"AF_COOKIE - {self.af_cookie}\nTimed out while pulling results", resp)

        return resp_data


class ScanRequest(APIRequest):

    class ResultRequest(ResultRequest):

        expected_size = 0
        actual_res_count = 0

        def __init__(self, *args, **kwargs):

            args = list(args)

            # We need to transform the request URL
            args[0] = "/" + args[0].split("/")[1] + "/results/" + kwargs.get("af_cookie", "")

            super().__init__(*args, **kwargs)
            self.expected_size = kwargs.get("expected_size", self.expected_size)

        def _check_if_results_complete(self, resp_data):

            # If we've gotten to 100%, it's time to stop iteration
            if not resp_data['af_in_progress']:

                if 'total' not in resp_data:
                    raise ServerError(f"AF_COOKIE - {self.af_cookie}\nServer sent malformed response, "
                                      "query complete but no total information in resp", resp_data)

                if self.actual_res_count != resp_data['total']:
                    # Sanity check
                    raise ServerError(f"AF_COOKIE - {self.af_cookie}\nExpecting {resp_data['total']} results, "
                                      f"but actually got {self.actual_res_count} while scanning", resp_data)
                return True

            return False

        def run(self):

            sleeper = GraduatingSleep()

            class _done_processing(Exception):
                pass

            async def _async_do():
                try:
                    return await self.api_request()
                except AutoFocusException:
                    raise
                except Exception:
                    raise ServerError(f"AF_COOKIE - {self.af_cookie}\nServer sent malformed response", None)

            def _do():
                try:
                    return self.api_request()
                except AutoFocusException:
                    raise
                except Exception:
                    raise ServerError(f"AF_COOKIE - {self.af_cookie}\nServer sent malformed response", None)

            def _post(resp):
                self._validate_response(resp)
                resp_data = resp['json']

                self.actual_res_count += len(resp_data.get('hits', []))

                if 'hits' in resp_data and resp_data['hits']:
                    return resp_data

                if self._check_if_results_complete(resp_data):
                    raise _done_processing()

                return {}

            if not self.async_request:
                def _not_coro():
                    try:
                        while True:
                            try:
                                res = _post(_do())
                                for hit in res.get("hits", []):
                                    yield hit
                                sleeper.sleep()
                            except _done_processing:
                                return
                    except GrauduatingSleepError:
                        raise ServerError("Server timed out pulling results")
                return _not_coro()

            async def _coro():
                try:
                    while True:
                        try:
                            res = _post(await _async_do())
                            for res in res.get('hits', []):
                                yield res
                            await sleeper.sleep(async_sleep=True)
                        except _done_processing:
                            return
                except GrauduatingSleepError:
                    raise ServerError("Server timed out pulling results")

            return _coro()

    def run(self):

        if not self.async_request:
            init_query_resp = self.api_request()
            init_query_data = init_query_resp['json']
            self.af_cookie = init_query_data['af_cookie']

            return self.ResultRequest(self.path, af_cookie=self.af_cookie).run()

        async def _coro():

            init_query_resp = await self.api_request()
            init_query_data = init_query_resp['json']
            self.af_cookie = init_query_data['af_cookie']

            async for res in self.ResultRequest(self.path, af_cookie=self.af_cookie,
                                                async_request=self.async_request).run():
                yield res

        return _coro()


class SearchRequest(APIRequest):

    page_size = 2000

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self.post_data["size"] = self.post_data.get("size", self.page_size)
        self.post_data["from"] = 0

    class ResultRequest(ResultRequest):
        pass

    def run(self):

        class _done_processing(Exception):
            pass

        def _prep():

            # If this search pages
            # if self.post_data.get("from") and self.post_data.get("size"):
            if "from" in self.post_data and 'size' in self.post_data:

                # Trim the page for the 4k limit on regular searches
                if self.post_data['from'] >= 4000:
                    raise _done_processing()

                if self.post_data['from'] + self.post_data['size'] > 4000:
                    self.post_data['size'] = 4000 - self.post_data['from']

        async def _async_do():
            return await self.api_request()

        def _do():
            return self.api_request()

        async def _async_post(init_query_data):

            self.post_data['from'] += self.post_data['size']
            self.af_cookie = init_query_data['json']['af_cookie']
            resp_data = await self.ResultRequest(self.path, af_cookie=self.af_cookie,
                                                 async_request=self.async_request).run()

            if not resp_data:
                raise _done_processing

            return resp_data

        def _post(init_query_data):

            self.post_data['from'] += self.post_data['size']
            self.af_cookie = init_query_data['json']['af_cookie']
            resp_data = self.ResultRequest(self.path, af_cookie=self.af_cookie, async_request=self.async_request).run()

            if not resp_data:
                raise _done_processing

            return resp_data

        sleeper = GraduatingSleep()

        if not self.async_request:
            def _not_coro():
                try:
                    while True:
                        try:
                            _prep()
                            res = _post(_do())
                            for hit in res.get("hits", []):
                                yield hit
                            sleeper.sleep()
                        except _done_processing:
                            return
                except GrauduatingSleepError:
                    raise ServerError("Server timed out pulling results")
            return _not_coro()

        async def _coro():
            try:
                while True:
                    try:
                        _prep()
                        res = await _async_post(await _async_do())
                        for hit in res.get("hits", []):
                            yield hit
                        await sleeper.sleep(async_sleep=True)
                    except _done_processing:
                        return
            except GrauduatingSleepError:
                raise ServerError("Server timed out pulling results")
        return _coro()


class CountRequest(SearchRequest):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        # Be gentle, we're only going to pull 1 sample, since we're not using it
        self.post_data['size'] = 1

    class ResultRequest(ResultRequest):

        def _check_if_results_complete(self, resp_data):
            if resp_data.get('af_complete_percentage', 100) == 100:
                return True
            return False

        def _validate_response(self, resp):

            super()._validate_response(resp)

            resp_data = resp.get("json", {})

            if self._check_if_results_complete(resp_data) and 'total' not in resp_data:
                raise ServerError("Server sent malformed response, total missing", resp)

    async def _async_run(self):

        init_query_resp = await self.api_request()
        init_query_data = init_query_resp['json']
        self.af_cookie = init_query_data['af_cookie']

        resp_data = await self.ResultRequest(self.path,
                                             af_cookie=self.af_cookie,
                                             async_request=self.async_request).run()

        return resp_data['total']

    def run(self):

        if self.async_request:
            return self._async_run()

        init_query_resp = self.api_request()
        init_query_data = init_query_resp['json']
        self.af_cookie = init_query_data['af_cookie']

        resp_data = self.ResultRequest(self.path, af_cookie=self.af_cookie).run()

        return resp_data['total']


class AggRequest(SearchRequest):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self.post_data["size"] = self.post_data.get("size", self.page_size)
        # Agg requests don't have a from argument
        del self.post_data['from']

    class ResultRequest(ResultRequest):

        def _build_url(self, *args, **kwargs):
            return "/" + args[0].split("/")[1] + "/aggregate/results/" + kwargs.get("af_cookie", "")

        def _validate_response(self, resp):

            super()._validate_response(resp)

            if 'aggregations' not in resp.get("json", {}):
                raise ServerError("Server sent malformed response, aggregations missing", resp)

        def _check_if_results_complete(self, resp_data):
            if resp_data.get('af_complete_percentage', 100) == 100:
                return True
            return False

    def _validate_response(self, resp):

        if 'aggregations' not in resp.get("json", {}):
            raise ServerError("Server sent malformed response, aggregations missing", resp)

    async def _async_run(self):

        init_query_resp = await self.api_request()
        init_query_data = init_query_resp['json']
        self.af_cookie = init_query_data['af_cookie']

        resp_data = await self.ResultRequest(self.path,
                                             af_cookie=self.af_cookie,
                                             async_request=self.async_request).run()

        return resp_data['aggregations']

    def run(self):

        if self.async_request:
            return self._async_run()

        init_query_resp = self.api_request()
        init_query_data = init_query_resp['json']
        self.af_cookie = init_query_data['af_cookie']

        resp_data = self.ResultRequest(self.path, af_cookie=self.af_cookie).run()

        return resp_data['aggregations']


class AutoFocusAPI(BaseFactory, metaclass=classproperty.meta):
    """
    The AutoFocusAPI is a base class for factory classes in this module to inherit from. This class is not meant for
    general use and is core to this underlying client library
    """

    @classproperty
    def api_key(cls):
        """Proxy access to the API key to the APIRequest class to maintain backward compatibility"""
        return APIRequest.api_key

    @api_key.setter
    def api_key(cls, value):
        """Proxy access to the API key to the APIRequest class to maintain backward compatibility"""
        APIRequest.api_key = value

    def _api_request(self, path, post_data=None):
        return APIRequest(path, post_data=post_data or {}, async_request=self.async_request).run()

    def _api_count(self, path, query, scope):
        post_data = {"query": query}
        if scope:
            post_data['scope'] = scope
        return CountRequest(path, post_data=post_data, async_request=self.async_request).run()

    def _handle_generator_results(self, req_class, path, post_data, limit, async_req=None):

        if not self.async_request:
            def _not_coro():
                count = 0
                for res in req_class(path, post_data=post_data, async_req=async_req).run():
                    yield res
                    count += 1
                    if count >= limit > 0:
                        break

            return _not_coro()

        async def _coro():
            count = 0

            async for res in req_class(path, post_data=post_data, async_request=self.async_request).run():
                yield res
                count += 1
                if limit is not None and count >= limit > 0:
                    break
        return _coro()

    def _api_scan(self, path, query, scope=None, fields=None, limit=None):
        post_data = {
            "query": query,
            "type": "scan"
        }

        optional_post_data = (
            ('scope', scope),
            ('fields', fields),
        )
        post_data = {**post_data, **{k: v for k, v in optional_post_data if v is not None}}

        return self._handle_generator_results(ScanRequest, path, post_data, limit)

    def _api_search(self, path, query, scope=None, sort_by=None, sort_dir=None, fields=None, limit=None,
                    type=None, page_size=None):

        post_data = {
            "query": query,
        }

        optional_post_data = (
            ('size', page_size),
            ('scope', scope),
            ('fields', fields),
            ('type', type),
            ('sort_by', sort_by),
            ('sort_dir', sort_dir)
        )
        post_data = {**post_data, **{k: v for k, v in optional_post_data if v is not None}}

        return self._handle_generator_results(SearchRequest, path, post_data, limit)
