from httmock import urlmatch, response
import requests
from . import mock_json
import pprint

API_HOST = 'SET HOST'
HEADERS = {"content-type": "application/json"}

mock_list = []


def register_mock(func):
    """Add a mock to the list of mocks that httmock will use.

    Add to the front of the list so mocks are loaded in the order they are defined.
    """
    mock_list.insert(0, func)
    return func


def serialize_request(req):
    if req.original.headers.get("x-apikey"):
        del req.original.headers['x-apikey']
    if req.headers.get("x-apikey"):
        del req.headers['x-apikey']
    return pprint.pformat({"original": {"auth": req.original.auth,
                                        "cookies": req.original.cookies,
                                        "data": req.original.data,
                                        "files": req.original.files,
                                        "headers": req.original.headers,
                                        "hooks": req.original.hooks,
                                        "json": req.original.json,
                                        "method": req.original.method,
                                        "params": req.original.params,
                                        "url": req.original.url},
                           "prepared": {"body": req.body,
                                        "headers": req.headers,
                                        "hooks": req.hooks,
                                        "method": req.method,
                                        "path_url": req.path_url,
                                        "url": req.url}}, indent=4)


def serialize_url(url):
    return pprint.pformat({"scheme": url.scheme,
                           "netloc": url.netloc,
                           "path": url.path,
                           "query": url.query,
                           "fragment": url.fragment})


@register_mock
@urlmatch(netloc=".*")
def fallback(url, request):
    raise AssertionError("A route hasn't been mocked for {}. Check the order of your mocks. Request info(auth-stripped):\n{}\nURL object info:\n{}".format(
        url.path, serialize_request(request), serialize_url(url)))


@register_mock
@urlmatch(netloc=API_HOST, path="/conn_error")
def conn_error(url, request):
    raise requests.exceptions.ConnectionError()


@register_mock
@urlmatch(netloc=API_HOST, path='/test/200')
def simple_200(url, request):
    return response(200, {"message": "got test 200"}, HEADERS, None, 5, request)


@register_mock
@urlmatch(netloc=API_HOST, path='/test/300')
def simple_300(url, request):
    return response(300, {"message": "got test 300"}, HEADERS, None, 5, request)


@register_mock
@urlmatch(netloc=API_HOST, path='/test/400')
def simple_400(url, request):
    return response(400, {"message": "got test 400"}, HEADERS, None, 5, request)


@register_mock
@urlmatch(netloc=API_HOST, path='/test/500')
def simple_500(url, request):
    return response(500, {"message": "got test 500"}, HEADERS, None, 5, request)
