from . import mocks
import pytest
from httmock import HTTMock


@pytest.yield_fixture(autouse=True)
def enable_htt_mocks():
    with HTTMock(*mocks.mock_list):
        yield
