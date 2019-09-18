class BaseException(Exception):
    pass


class AutoFocusException(BaseException):
    pass


class RedirectError(AutoFocusException):
    """
    Notes:
        RedirectError is an exception that's thrown when the client library is being redirected. All URLs should be
        direct and not require a redirect
    Args:
        message (str): Message describing the error
        response (requests.Response): The response from the server in the case of on invalid request
    """
    def __init__(self, message, response):
        #: str: a message describing the error
        self.message = message
        #: requests.Response: response from the server
        self.response = response


class ClientError(AutoFocusException):
    """
    Notes:
        ClientError is an exception that's thrown when the client library is either used improperly, or offers invalid
        data to the AutoFocus REST service
    Args:
        message (str): Message describing the error
        Optional[requests.Response] response: the response from the server in the case of on invalid request
    """
    def __init__(self, message, response=None):
        super(ClientError, self).__init__(self, message)
        #: str: a message describing the error
        self.message = message
        #: Optional[requests.Response]: response from the server (May be None)
        self.response = response


class ServerError(AutoFocusException):
    """
    Notes:
        ServerError is an exception that's thrown when the AutoFocus REST service behaves unexpectedly
    Args:
        message (str): Message describing the error
        response Optional[requests.Response]: the response from the server in the case of on invalid request
    """
    def __init__(self, message, response=None):
        super(ServerError, self).__init__(self, message)
        #: str: a message describing the error
        self.message = message
        #: requests.Response: response from the server
        self.response = response


class SampleAbsent(AutoFocusException, KeyError):
    pass


class TagAbsent(AutoFocusException, KeyError):
    pass


class TagGroupAbsent(AutoFocusException, KeyError):
    pass


class _InvalidSampleData(Exception):
    """
    Private class meant to be used for skipping bad sample rows
    """
    pass


class _InvalidAnalysisData(Exception):
    """
    Private class meant to be used for skipping bad analysis data rows
    """
    pass


class GrauduatingSleepError(AutoFocusException):
    pass
