import os.path
import logging
import socket
from base64 import b64encode

from urllib3 import PoolManager, ProxyManager, proxy_from_url, Timeout
from urllib3.exceptions import ReadTimeoutError as URLLib3ReadTimeoutError
from urllib3.exceptions import (
    NewConnectionError, ProtocolError, ProxyError, ConnectTimeoutError
)

import botocore.awsrequest
from botocore.vendored import six
from botocore.vendored.six.moves.urllib_parse import unquote
from botocore.compat import filter_ssl_warnings, urlparse
from botocore.exceptions import (
    ConnectionClosedError, EndpointConnectionError, HTTPClientError,
    ReadTimeoutError, ProxyConnectionError
)
try:
    from urllib3.contrib import pyopenssl
    pyopenssl.extract_from_urllib3()
except ImportError:
    pass

filter_ssl_warnings()
logger = logging.getLogger(__name__)
DEFAULT_TIMEOUT = 60
MAX_POOL_CONNECTIONS = 10
DEFAULT_CA_BUNDLE = os.path.join(os.path.dirname(__file__), 'cacert.pem')

try:
    from certifi import where
except ImportError:
    def where():
        return DEFAULT_CA_BUNDLE


def get_cert_path(verify):
    if verify is not True:
        return verify

    return where()


class ProxyConfiguration(object):
    """Represents a proxy configuration dictionary.

    This class represents a proxy configuration dictionary and provides utility
    functions to retreive well structured proxy urls and proxy headers from the
    proxy configuration dictionary.
    """
    def __init__(self, proxies=None):
        if proxies is None:
            proxies = {}
        self._proxies = proxies

    def proxy_url_for(self, url):
        """Retrirves the corresponding proxy url for a given url. """
        parsed_url = urlparse(url)
        proxy = self._proxies.get(parsed_url.scheme)
        if proxy:
            proxy = self._fix_proxy_url(proxy)
        return proxy

    def proxy_headers_for(self, proxy_url):
        """Retrirves the corresponding proxy headers for a given proxy url. """
        headers = {}
        username, password = self._get_auth_from_url(proxy_url)
        if username and password:
            basic_auth = self._construct_basic_auth(username, password)
            headers['Proxy-Authorization'] = basic_auth
        return headers

    def _fix_proxy_url(self, proxy_url):
        if proxy_url.startswith('http:') or proxy_url.startswith('https:'):
            return proxy_url
        elif proxy_url.startswith('//'):
            return 'http:' + proxy_url
        else:
            return 'http://' + proxy_url

    def _construct_basic_auth(self, username, password):
        auth_str = '{0}:{1}'.format(username, password)
        encoded_str = b64encode(auth_str.encode('ascii')).strip().decode()
        return 'Basic {0}'.format(encoded_str)

    def _get_auth_from_url(self, url):
        parsed_url = urlparse(url)
        try:
            return unquote(parsed_url.username), unquote(parsed_url.password)
        except (AttributeError, TypeError):
            return None, None


class URLLib3Session(object):
    """A basic HTTP client that supports connection pooling and proxies.

    This class is inspired by requests.adapters.HTTPAdapter, but has been
    boiled down to meet the use cases needed by botocore. For the most part
    this classes matches the functionality of HTTPAdapter in requests v2.7.0
    (the same as our vendored version). The only major difference of note is
    that we currently do not support sending chunked requests. While requests
    v2.7.0 implemented this themselves, later version urllib3 support this
    directly via a flag to urlopen so enabling it if needed should be trivial.
    """
    def __init__(self,
                 verify=True,
                 proxies=None,
                 timeout=None,
                 max_pool_connections=MAX_POOL_CONNECTIONS,
    ):
        self._verify = verify
        self._proxy_config = ProxyConfiguration(proxies=proxies)
        if timeout is None:
            timeout = DEFAULT_TIMEOUT
        if not isinstance(timeout, (int, float)):
            timeout = Timeout(connect=timeout[0], read=timeout[1])
        self._timeout = timeout
        self._max_pool_connections = max_pool_connections
        self._proxy_managers = {}
        self._manager = PoolManager(
            strict=True,
            timeout=self._timeout,
            maxsize=self._max_pool_connections,
        )

    def _get_proxy_manager(self, proxy_url):
        if proxy_url not in self._proxy_managers:
            proxy_headers = self._proxy_config.proxy_headers_for(proxy_url)
            self._proxy_managers[proxy_url] = proxy_from_url(
                proxy_url,
                strict=True,
                timeout=self._timeout,
                proxy_headers=proxy_headers,
                maxsize=self._max_pool_connections
            )

        return self._proxy_managers[proxy_url]

    def _path_url(self, url):
        parsed_url = urlparse(url)
        path = parsed_url.path
        if not path:
            path = '/'
        if parsed_url.query:
            path = path + '?' + parsed_url.query
        return path

    def _setup_ssl_cert(self, conn, url, verify):
        if url.lower().startswith('https') and verify:
            conn.cert_reqs = 'CERT_REQUIRED'
            conn.ca_certs = get_cert_path(verify)
        else:
            conn.cert_reqs = 'CERT_NONE'
            conn.ca_certs = None

    def send(self, request):
        try:
            request_target = self._path_url(request.url)

            proxy_url = self._proxy_config.proxy_url_for(request.url)
            if proxy_url:
                manager = self._get_proxy_manager(proxy_url)
            else:
                manager = self._manager

            if proxy_url and request.url.startswith('http:'):
                # If an http request is being proxied use the full url
                request_target = request.url

            conn = manager.connection_from_url(request.url)
            self._setup_ssl_cert(conn, request.url, self._verify)
            urllib_response = conn.urlopen(
                method=request.method,
                url=request_target,
                body=request.body,
                headers=request.headers,
                retries=False,
                assert_same_host=False,
                preload_content=False,
                decode_content=False,
            )

            http_response = botocore.awsrequest.AWSResponse(
                request.url,
                urllib_response.status,
                urllib_response.headers,
                urllib_response,
            )

            if not request.stream_output:
                # Cause the raw stream to be exhausted immediately. We do it
                # this way instead of using preload_content because
                # preload_content will never buffer chunked responses
                http_response.content

            return http_response
        except (NewConnectionError, ConnectTimeoutError, socket.gaierror) as e:
            raise EndpointConnectionError(endpoint_url=request.url, error=e)
        except URLLib3ReadTimeoutError as e:
            raise ReadTimeoutError(endpoint_url=request.url, error=e)
        except ProxyError as e:
            raise ProxyConnectionError(proxy_url=proxy_url, error=e)
        except ProtocolError as e:
            raise ConnectionClosedError(
                error=e,
                request=request,
                endpoint_url=request.url
            )
        except Exception as e:
            raise HTTPClientError(error=e)


try:
    from botocore.vendored._hyper.http20.connection import HTTP20Connection
    from botocore.vendored._hyper.compat import urlparse, ssl
    from botocore.vendored._hyper.tls import init_context
    from botocore.vendored._hyper.common.util import to_native_string
    from botocore.vendored._hyper.common import exceptions as hyper_errors
except ImportError:
    # Hyper is an optional dependency
    pass


class HyperSession(object):
    """
    A Requests Transport Adapter that uses hyper to send requests over
    HTTP/2. This implements some degree of connection pooling to maximise the
    HTTP/2 gain.
    """
    def __init__(self,
                 verify=True,
                 proxies=None,
                 timeout=None,
                 max_pool_connections=MAX_POOL_CONNECTIONS,
    ):
        self._verify = verify
        self._proxy_config = ProxyConfiguration(proxies=proxies)
        if timeout is None:
            timeout = DEFAULT_TIMEOUT
        self._timeout = timeout
        self._max_pool_connections = max_pool_connections
        self._connections = {}

    def _get_connection(self, host, port, scheme, cert=None, verify=True,
                        proxy=None, timeout=None):
        """
        Gets an appropriate HTTP/2 connection object based on
        host/port/scheme/cert tuples.
        """
        secure = (scheme == 'https')

        if port is None:  # pragma: no cover
            port = 80 if not secure else 443

        if proxy:
            proxy_headers = self._proxy_config.proxy_headers_for(proxy)
            proxy_netloc = urlparse(proxy).netloc
        else:
            proxy_headers = None
            proxy_netloc = None

        # We put proxy headers in the connection_key, because
        # ``proxy_headers`` method might be overridden, so we can't
        # rely on proxy headers being the same for the same proxies.
        proxy_headers_key = (frozenset(proxy_headers.items())
                             if proxy_headers else None)
        connection_key = (host, port, scheme, cert, verify,
                          proxy_netloc, proxy_headers_key)
        try:
            conn = self._connections[connection_key]
        except KeyError:

            ssl_context = None
            if not verify:
                verify = False
                cert_path = DEFAULT_CA_BUNDLE
                ssl_context = init_context(cert_path=cert_path, cert=cert)
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            else:
                cert_path = get_cert_path(verify)
                ssl_context = init_context(cert_path=cert_path, cert=cert)

            conn = HTTP20Connection(
                host,
                port,
                secure=secure,
                ssl_context=ssl_context,
                proxy_host=proxy_netloc,
                proxy_headers=proxy_headers,
                timeout=timeout,
                force_proto='h2',
            )
            self._connections[connection_key] = conn

        return conn

    def send(self, request):
        """
        Sends a HTTP message to the server.
        """
        try:
            proxy_url = self._proxy_config.proxy_url_for(request.url)
            parsed = urlparse(request.url)
            if isinstance(request.body, str):
                request.body = request.body.encode('utf-8')
            conn = self._get_connection(
                parsed.hostname,
                parsed.port,
                parsed.scheme,
                verify=self._verify,
                proxy=proxy_url,
                timeout=self._timeout)

            # Build the selector.
            selector = parsed.path
            selector += '?' + parsed.query if parsed.query else ''
            selector += '#' + parsed.fragment if parsed.fragment else ''

            conn.request(
                request.method,
                selector,
                request.body,
                request.headers
            )
            hyper_response = conn.get_response()

            def ghetto_stream(self, amt=2**16, decode_content=None):
                while True:
                    chunk = self.read(amt, decode_content=decode_content)
                    if not chunk:
                        break
                    yield chunk

            hyper_response.stream = ghetto_stream.__get__(hyper_response)

            http_response = botocore.awsrequest.AWSResponse(
                request.url,
                hyper_response.status,
                (map(to_native_string, h) for h in hyper_response.headers.items()),
                hyper_response
            )

            if not request.stream_output:
                # Cause the raw stream to be exhausted immediately. We do it
                # this way instead of using preload_content because
                # preload_content will never buffer chunked responses
                http_response.content

            return http_response
        except (hyper_errors.NewConnectionError, hyper_errors.ConnectionTimeoutError) as e:
            raise EndpointConnectionError(endpoint_url=request.url, error=e)
        except hyper_errors.ProxyError as e:
            raise ProxyConnectionError(proxy_url=proxy_url, error=e)
        except hyper_errors.ReadTimeoutError as e:
            raise ReadTimeoutError(endpoint_url=request.url, error=e)
        except hyper_errors.ConnectionResetError as e:
            raise ConnectionClosedError(
                error=e,
                request=request,
                endpoint_url=request.url
            )
        except Exception as e:
            raise HTTPClientError(error=e)

    def close(self):
        for connection in self._connections.values():
            connection.close()
        self._connections.clear()
