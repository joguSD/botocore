# -*- coding: utf-8 -*-
"""
hyper/common/exceptions
~~~~~~~~~~~~~~~~~~~~~~~

Contains hyper's exceptions.
"""


class ChunkedDecodeError(Exception):
    """
    An error was encountered while decoding a chunked response.
    """
    pass


class InvalidResponseError(Exception):
    """
    A problem was found with the response that makes it invalid.
    """
    pass


class SocketError(Exception):
    """
    An error occurred during socket operation.
    """
    pass


class LineTooLongError(Exception):
    """
    An attempt to read a line from a socket failed because no newline was
    found.
    """
    pass


# Create our own ConnectionResetError.
try:  # pragma: no cover
    ConnectionResetError = ConnectionResetError
except NameError:  # pragma: no cover
    class ConnectionResetError(Exception):
        """
        A HTTP connection was unexpectedly reset.
        """


class TLSUpgrade(Exception):
    """
    We upgraded to a new protocol in the NPN/ALPN handshake.
    """
    def __init__(self, negotiated, sock):
        super(TLSUpgrade, self).__init__()
        self.negotiated = negotiated
        self.sock = sock


class HTTPUpgrade(Exception):
    """
    We upgraded to a new protocol via the HTTP Upgrade response.
    """
    def __init__(self, negotiated, sock):
        super(HTTPUpgrade, self).__init__()
        self.negotiated = negotiated
        self.sock = sock


class MissingCertFile(Exception):
    """
    The certificate file could not be found.
    """
    pass


try:
    TimeoutError = TimeoutError
except NameError:
    class TimeoutError(Exception):
        """
        A socket operation timed out.
        """


class ReadTimeoutError(TimeoutError):
    """
    A socket timed out while attempting to be read.
    """


# Create our own ConnectionError.
try:  # pragma: no cover
    ConnectionError = ConnectionError
except NameError:  # pragma: no cover
    class ConnectionError(Exception):
        """
        An error occurred during connection to a host.
        """


class ProtocolNegotiationError(ConnectionError):
    """
    Attempt to negotiate H2 via ALPN failed.
    """


class ConnectionTimeoutError(TimeoutError, ConnectionError):
    """
    Attempt to create a new connection to host timed out.
    """


class NewConnectionError(ConnectionError):
    """
    Failed to establish a new connection.
    """


class ProxyError(ConnectionError):
    """
    An error occurred during connection to a proxy.
    """
    def __init__(self, message, response):
        self.response = response
        super(ProxyError, self).__init__(message)
