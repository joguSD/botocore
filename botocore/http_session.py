import os.path
import logging
import socket
from base64 import b64encode

from urllib3 import PoolManager, ProxyManager, proxy_from_url, Timeout
from urllib3.exceptions import NewConnectionError, ProtocolError

from botocore.vendored import six
from botocore.vendored.six.moves.urllib_parse import unquote
from botocore.awsrequest import AWSResponse
from botocore.compat import filter_ssl_warnings, urlparse
from botocore.exceptions import ConnectionClosedError, EndpointConnectionError
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
    def __init__(self, proxies=None):
        if proxies is None:
            proxies = {}
        self._proxies = proxies

    def proxy_url_for(self, url):
        parsed_url = urlparse(url)
        proxy = self._proxies.get(parsed_url.scheme)
        if proxy:
            proxy = self._fix_proxy_url(proxy)
        return proxy

    def proxy_headers_for(self, proxy_url):
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

            proxy = self._proxy_config.proxy_url_for(request.url)
            if proxy:
                manager = self._get_proxy_manager(proxy)
            else:
                manager = self._manager

            if proxy and request.url.startswith('http:'):
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

            http_response = AWSResponse(
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
        except (NewConnectionError, socket.gaierror) as e:
            raise EndpointConnectionError(endpoint_url=request.url, error=e)
        except ProtocolError as e:
            raise ConnectionClosedError(
                request=request,
                endpoint_url=request.url
            )
