import autofocus

from unittest import TestCase
import pytest
import datetime
import decimal


class TestAFExceptions(TestCase):

    def test_AFRedirectError(self):
        afre = autofocus.AFRedirectError("msg", "resp")
        assert afre.message == "msg"
        assert afre.response == "resp"

    def test_AFClientError(self):
        afce = autofocus.AFClientError("msg", "resp")
        assert afce.message == "msg"
        assert afce.response == "resp"

    def test_AFServerError(self):
        afse = autofocus.AFServerError("msg", "resp")
        assert afse.message == "msg"
        assert afse.response == "resp"


class TestAFObject(TestCase):

    def test_serialize_include(self):
        afo = autofocus.AutoFocusObject()
        afo.int = 1
        afo.dict = {'key': 'val'}
        afo.date = datetime.datetime(year=2000, month=1, day=1)
        afo.dec = decimal.Decimal("1.22222")
        afo.lazy = autofocus.NotLoaded()
        out = afo.serialize()
        assert out['int'] == 1
        assert out['dict'] == {'key': 'val'}
        assert out['date'] == "2000-01-01T00:00:00"
        assert out['dec'] == "1.2"
        assert out['lazy'] is None

    def test_serialize_dont_include(self):
        afo = autofocus.AutoFocusObject()
        afo.int = 1
        afo.dict = {'key': 'val'}
        afo.date = datetime.datetime(year=2000, month=1, day=1)
        afo.dec = decimal.Decimal("1.22222")
        afo.lazy = autofocus.NotLoaded()
        out = afo.serialize(include_all=False)
        assert out['int'] == 1
        assert out['dict'] == {'key': 'val'}
        assert out['date'] == "2000-01-01T00:00:00"
        assert out['dec'] == "1.2"
        with pytest.raises(KeyError):
            out['lazy']

    def test_serialize_depth(self):
        afo = autofocus.AutoFocusObject()
        assert afo.serialize(depth=0) is None
        afo2 = autofocus.AutoFocusObject()
        afo2.int = 1
        afo.lst = [afo2]
        afo.afo = afo2
        assert afo.serialize(depth=3)['lst'][0]['int'] == 1
        assert afo.serialize(depth=3)['afo'] == {'int': 1}
        with pytest.raises(KeyError):
            afo.serialize()['lst']
        assert afo.serialize().get('afo') is None


class TestAFAPI(TestCase):

    def test_no_api_key(self):
        api = autofocus.AutoFocusAPI()
        key_copy = autofocus.AutoFocusAPI.api_key = None
        with pytest.raises(autofocus.AFClientError):
            api._api_request("/test/200", api_key=None)
        autofocus.AutoFocusAPI.api_key = key_copy

    def test_api_request_200(self):
        api = autofocus.AutoFocusAPI()
        api._api_request("/test/200")

    def test_api_request_300(self):
        api = autofocus.AutoFocusAPI()
        with pytest.raises(autofocus.AFRedirectError):
            api._api_request("/test/300")

    def test_api_request_400(self):
        api = autofocus.AutoFocusAPI()
        with pytest.raises(autofocus.AFClientError):
            api._api_request("/test/400")

    def test_api_request_500(self):
        api = autofocus.AutoFocusAPI()
        with pytest.raises(autofocus.AFServerError):
            api._api_request("/test/500")

    def test_connection_error(self):
        api = autofocus.AutoFocusAPI()
        with pytest.raises(autofocus.AFServerError):
            api._api_request("/conn_error")
